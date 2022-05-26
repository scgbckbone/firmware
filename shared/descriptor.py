# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# descriptor.py - Bitcoin Core's descriptors and their specialized checksums.
#
# Based on: https://github.com/bitcoin/bitcoin/blob/master/src/script/descriptor.cpp
#
from public_constants import AF_P2SH, AF_P2WSH_P2SH, AF_P2WSH

FMT_TO_SCRIPT = {
    AF_P2SH: "sh(%s)",
    AF_P2WSH_P2SH: "sh(wsh(%s))",
    AF_P2WSH: "wsh(%s)",
    None: "wsh(%s)",
    # hack for tests
    "p2sh": "sh(%s)",
    "p2sh-p2wsh": "sh(wsh(%s))",
    "p2wsh": "wsh(%s)",
}

try:
    from utils import xfp2str, str2xfp
except ModuleNotFoundError:
    import struct
    from binascii import unhexlify as a2b_hex
    from binascii import hexlify as b2a_hex
    # assuming not micro python
    def xfp2str(xfp):
        # Standardized way to show an xpub's fingerprint... it's a 4-byte string
        # and not really an integer. Used to show as '0x%08x' but that's wrong endian.
        return b2a_hex(struct.pack('<I', xfp)).decode().upper()

    def str2xfp(txt):
        # Inverse of xfp2str
        return struct.unpack('<I', a2b_hex(txt))[0]


def polymod(c, val):
    c0 = c >> 35
    c = ((c & 0x7ffffffff) << 5) ^ val
    if (c0 & 1):
        c ^= 0xf5dee51989
    if (c0 & 2):
        c ^= 0xa9fdca3312
    if (c0 & 4):
        c ^= 0x1bab10e32d
    if (c0 & 8):
        c ^= 0x3706b1677a
    if (c0 & 16):
        c ^= 0x644d626ffd

    return c

def descriptor_checksum(desc):
    INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
    CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

    c = 1
    cls = 0
    clscount = 0
    for ch in desc:
        pos = INPUT_CHARSET.find(ch)
        if pos == -1:
            raise ValueError(ch)

        c = polymod(c, pos & 31)
        cls = cls * 3 + (pos >> 5)
        clscount += 1
        if clscount == 3:
            c = polymod(c, cls)
            cls = 0
            clscount = 0

    if clscount > 0:
        c = polymod(c, cls)
    for j in range(0, 8):
        c = polymod(c, 0)
    c ^= 1

    rv = ''
    for j in range(0, 8):
        rv += CHECKSUM_CHARSET[(c >> (5 * (7 - j))) & 31]

    return rv

def append_checksum(desc):
    return desc + "#" + descriptor_checksum(desc)


class MultisigDescriptor:
    # only supprt with key derivation info
    # only xpubs
    # can be extended when needed
    __slots__ = (
        "M",
        "N",
        "keys",
        "addr_fmt",
        "xfp_subderiv",
    )

    def __init__(self, M, N, keys, addr_fmt, xfp_subderiv=None):
        self.M = M
        self.N = N
        self.keys = keys
        self.addr_fmt = addr_fmt
        if not xfp_subderiv:
            self.xfp_subderiv = {}
        else:
            self.xfp_subderiv = xfp_subderiv

    @classmethod
    def subpath2str(cls, subpath: list) -> str:
        assert subpath[-1] == "*"
        return subpath[:].join("/")

    @staticmethod
    def checksum_check(desc_w_checksum: str):
        try:
            desc, checksum = desc_w_checksum.split("#")
        except ValueError:
            raise ValueError("Missing descriptor checksum")
        calc_checksum = descriptor_checksum(desc)
        if calc_checksum != checksum:
            raise ValueError("Wrong checksum %s, expected %s" % (checksum, calc_checksum))
        return desc, checksum

    @staticmethod
    def parse_key_orig_info(key: str):
        # key origin info is required for our MultisigWallet
        close_index = key.find("]")
        if key[0] != "[" and close_index == -1:
            raise ValueError("Key origin info is required for %s" % (key))
        key_orig_info = key[1:close_index]  # remove brackets
        key = key[close_index + 1:]
        assert "/" in key_orig_info, "Malformed key derivation info"
        return key_orig_info, key

    @staticmethod
    def parse_key_derivation_info(key: str):
        slash_split = key.split("/")
        assert len(slash_split) > 1, "Only range descriptors are allowed, missing '*'"
        if all(["h" not in elem and "'" not in elem for elem in slash_split[1:]]):
            assert slash_split[-1] == "*", "Only range descriptors are allowed, missing '*'"
            return slash_split[0], tuple(slash_split[1:])
        else:
            raise ValueError("Cannot use hardened sub derivation path")

    def checksum(self):
        return descriptor_checksum(self._serialize())

    def serialize_keys(self):
        result = []
        for xfp, deriv, xpub in self.keys:
            if deriv[0] == "m":
                # get rid of 'm'
                deriv = deriv[1:]
            koi = xfp2str(xfp) + deriv
            key_str = "[%s]%s" % (koi.lower(), xpub)
            sub_deriv = self.xfp_subderiv.get(xfp, ["0", "*"])
            key_str = key_str + "/" + "/".join(sub_deriv) if sub_deriv else key_str
            result.append(key_str)
        return result

    @classmethod
    def parse(cls, desc_w_checksum: str) -> "MultisigDescriptor":
        # check correct checksum
        desc, checksum = cls.checksum_check(desc_w_checksum)
        # legacy
        if desc.startswith("sh(sortedmulti("):
            addr_fmt = AF_P2SH
            tmp_desc = desc.replace("sh(sortedmulti(", "")
            tmp_desc = tmp_desc.rstrip("))")

        # native segwit
        elif desc.startswith("wsh(sortedmulti("):
            addr_fmt = AF_P2WSH
            tmp_desc = desc.replace("wsh(sortedmulti(", "")
            tmp_desc = tmp_desc.rstrip("))")

        # wrapped segwit
        elif desc.startswith("sh(wsh(sortedmulti("):
            addr_fmt = AF_P2WSH_P2SH
            tmp_desc = desc.replace("sh(wsh(sortedmulti(", "")
            tmp_desc = tmp_desc.rstrip(")))")

        else:
            raise ValueError("Unsupported descriptor. Supported: sh(, sh(wsh(, wsh(. All has to be sortedmulti.")

        splitted = tmp_desc.split(",")
        M, keys = int(splitted[0]), splitted[1:]
        N = int(len(keys))
        if M > N:
            raise ValueError("Multisig threshold cannot be larger than the number of keys; "
                             "threshold is %d but only %d keys specified" % (M, N))

        res_keys = []
        xfp_subderiv = {}
        for key in keys:
            koi, key = cls.parse_key_orig_info(key)
            if key[0:4] not in ["tpub", "xpub"]:
                raise ValueError("Only extended public keys are supported")
            xpub, sub_deriv = cls.parse_key_derivation_info(key)
            xfp = str2xfp(koi[:8])
            if sub_deriv:
                xfp_subderiv[xfp] = sub_deriv
            origin_deriv = "m" + koi[8:]
            res_keys.append((xfp, origin_deriv, xpub))
        return cls(M=M, N=N, keys=res_keys, addr_fmt=addr_fmt, xfp_subderiv=xfp_subderiv)

    def _serialize(self) -> str:
        """Serialize without checksum"""
        desc_base = FMT_TO_SCRIPT[self.addr_fmt]
        desc_base = desc_base % ("sortedmulti(%s)")
        assert len(self.keys) == self.N, "invalid descriptor object"
        inner = str(self.M) + "," + ",".join(self.serialize_keys())
        return desc_base % (inner)

    def serialize(self) -> str:
        """Serialize with checksum"""
        return append_checksum(self._serialize())

# EOF
