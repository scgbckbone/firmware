# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# stuff I need sometimes
import random
from io import BytesIO
from binascii import b2a_hex, a2b_hex
from decimal import Decimal
from pysecp256k1 import tagged_sha256
from pysecp256k1.extrakeys import xonly_pubkey_serialize, xonly_pubkey_tweak_add, xonly_pubkey_from_pubkey
from pysecp256k1.extrakeys import xonly_pubkey_parse


def B2A(s):
    return str(b2a_hex(s), 'ascii')
    
def U2SAT(v):
    return int(v * Decimal('1E8'))

# use like this:
#
#       with into_hex() as a:
#           a.write('sdlkfjsdflkj')
#
# ... will print hex of whatever was streamed.
#
class into_hex(BytesIO):
    def __exit__(self, *a):
        print('hex: %s' % str(b2a_hex(self.getvalue()), 'ascii'))
        return super().__exit__(*a)

'''
    >>> from binascii import *
    >>> from helpers import into_hex
    >>> from pycoin.tx.Tx import Tx
    >>> t = Tx.from_hex('010000....')
    >>> with into_hex() as fd:
    >>>     t.txs_out[0].stream(fd)
'''

def dump_txos(hx, out_num=0):
    from binascii import b2a_hex
    from helpers import into_hex
    from pycoin.tx.Tx import Tx

    t = Tx.from_hex(hx)
    with into_hex() as fd:
        t.txs_out[out_num].stream(fd)

    print('hash160: %s' % b2a_hex(t.txs_out[out_num].hash160()))

    return t

def prandom(count):
    # make some bytes, randomly, but not: deterministic
    return bytes(random.randint(0, 255) for i in range(count))

def taptweak(internal_key, tweak=None):
    tweak = internal_key if tweak is None else internal_key + tweak
    assert len(internal_key) == 32, "not xonly-pubkey (len!=32)"
    xonly_pubkey = xonly_pubkey_parse(internal_key)
    tweak = tagged_sha256(b"TapTweak", tweak)
    tweaked_pubkey = xonly_pubkey_tweak_add(xonly_pubkey, tweak)
    tweaked_xonnly_pubkey, parity = xonly_pubkey_from_pubkey(tweaked_pubkey)
    return xonly_pubkey_serialize(tweaked_xonnly_pubkey)

def fake_dest_addr(style='p2pkh'):
    # Make a plausible output address, but it's random garbage. Cant use for change outs

    # See CTxOut.get_address() in ../shared/serializations

    if style == 'p2wpkh':
        return bytes([0, 20]) + prandom(20)

    if style == 'p2wsh':
        return bytes([0, 32]) + prandom(32)

    if style in ['p2sh', 'p2wsh-p2sh', 'p2wpkh-p2sh']:
        # all equally bogus P2SH outputs
        return bytes([0xa9, 0x14]) + prandom(20) + bytes([0x87])

    if style == 'p2pkh':
        return bytes([0x76, 0xa9, 0x14]) + prandom(20) + bytes([0x88, 0xac])

    if style == "p2tr":
        return bytes([81, 32]) + prandom(32)

    # missing: if style == 'p2pk' =>  pay to pubkey, considered obsolete

    raise ValueError('not supported: ' + style)

def make_change_addr(wallet, style):
    # provide script, pubkey and xpath for a legit-looking change output
    import struct, random
    from pycoin.encoding import hash160

    redeem_scr, actual_scr = None, None
    deriv = [12, 34, random.randint(0, 1000)]

    xfp, = struct.unpack('I', wallet.fingerprint())

    dest = wallet.subkey_for_path('/'.join(str(i) for i in deriv))

    target = dest.hash160()
    assert len(target) == 20

    is_segwit = True
    if style == 'p2pkh':
        redeem_scr = bytes([0x76, 0xa9, 0x14]) + target + bytes([0x88, 0xac])
        is_segwit = False
    elif style == 'p2wpkh':
        redeem_scr = bytes([0, 20]) + target
    elif style == 'p2wpkh-p2sh':
        redeem_scr = bytes([0, 20]) + target
        actual_scr = bytes([0xa9, 0x14]) + hash160(redeem_scr) + bytes([0x87])
    elif style == 'p2tr':
        tweaked_xonly = taptweak(dest.sec()[1:])
        redeem_scr = bytes([81, 32]) + tweaked_xonly
        return redeem_scr, actual_scr, is_segwit, dest.sec()[1:], b'\x00' + struct.pack('4I', xfp, *deriv)
    else:
        raise ValueError('cant make fake change output of type: ' + style)

    return redeem_scr, actual_scr, is_segwit, dest.sec(), struct.pack('4I', xfp, *deriv)

def swab32(n):
    # endian swap: 32 bits
    import struct
    return struct.unpack('>I', struct.pack('<I', n))[0]

def xfp2str(xfp):
    # Standardized way to show an xpub's fingerprint... it's a 4-byte string
    # and not really an integer. Used to show as '0x%08x' but that's wrong endian.
    from binascii import b2a_hex
    from struct import pack
    return b2a_hex(pack('<I', xfp)).decode('ascii').upper()

def parse_change_back(story):

    lines = story.split('\n')
    s = lines.index('Change back:')
    assert s > 3
    assert 'XTN' in lines[s+1] or 'XRT' in lines[s+1] or 'BTC' in lines[s+1]
    val = Decimal(lines[s+1].split()[0])
    assert 'address' in lines[s+2]
    addrs = []
    for y in range(s+3, len(lines)):
        if not lines[y]: break
        addrs.append(lines[y])

    if len(addrs) >= 2:
        assert 'to addresses' in lines[s+2]

    return val, addrs

def path_to_str(bin_path, prefix='m/', skip=1):
    return prefix + '/'.join(str(i & 0x7fffffff) + ("'" if i & 0x80000000 else "")
                            for i in bin_path[skip:])

def str_to_path(path):
    # Take string derivation path, and make a list of numbers,
    # - no syntax checking here

    assert path[0:2] == 'm/'

    rv = []
    for p in path.split('/'):
        if p == 'm': continue
        if not p: continue      # trailing or duplicated slashes

        if p[-1] == "'":
            here = int(p[:-1]) | 0x80000000
        else:
            here = int(p)

        rv.append(here)

    assert path == path_to_str(rv, skip=0)

    return rv

def slip132undo(orig):
    # take a SLIP-132 xpub/ypub/z/U/?pub/prv and convert into BIP-32 style
    # - preserve testnet vs. mainnet
    # - return addr fmt info
    from pycoin.encoding import a2b_hashed_base58, b2a_hashed_base58
    from ckcc_protocol.constants import AF_P2WPKH_P2SH, AF_P2SH, AF_P2WSH, AF_P2WSH_P2SH, AF_CLASSIC
    from ckcc_protocol.constants import AF_P2WPKH


    assert orig[0] not in 'xt', "already legit bip32"

    xpub = a2b_hex('0488B21E')
    tpub = a2b_hex('043587cf')
    xprv = a2b_hex('0488ADE4')
    tprv = a2b_hex('04358394')

    variants  = [
        (False, AF_P2WPKH_P2SH, '049d7cb2', '049d7878', 'y'),
        (False, AF_P2WPKH, '04b24746', '04b2430c', 'z'),
        (False, AF_P2WSH_P2SH, '0295b43f', '0295b005', 'Y'),
        (False, AF_P2WSH, '02aa7ed3', '02aa7a99', 'Z'),
        (True, AF_P2WPKH_P2SH, '044a5262', '044a4e28', 'u'),
        (True, AF_P2WPKH, '045f1cf6', '045f18bc', 'v'),
        (True, AF_P2WSH_P2SH, '024289ef', '024285b5', 'U'),
        (True, AF_P2WSH, '02575483', '02575048', 'V'),
    ]

    raw = a2b_hashed_base58(orig)

    for testnet, addr_fmt, pub, priv, hint in variants:

        if raw[0:4] == a2b_hex(pub):
            return b2a_hashed_base58((tpub if testnet else xpub) + raw[4:]), \
                        testnet, addr_fmt, False

        if raw[0:4] == a2b_hex(priv):
            return b2a_hashed_base58((tprv if testnet else xprv) + raw[4:]), \
                        testnet, addr_fmt, True

    raise RuntimeError("unknown prefix")

def sign_msg(key, msg, addr_fmt, b64 = False):
    from ckcc_protocol.constants import AF_CLASSIC, AF_P2WPKH_P2SH, AF_P2WPKH

    # signs some bytes Bitcoin style using pycoin
    from pycoin.contrib.msg_signing import sign_message
    from pycoin.key.key_from_text import key_from_text
    from pycoin.encoding import from_bytes_32, double_sha256
    from base64 import b64decode, b64encode
    from psbt import ser_compact_size

    preimage = b'\x18Bitcoin Signed Message:\n' + ser_compact_size(len(msg)) + msg
    md = double_sha256(preimage)
    md = from_bytes_32(md)
    sig = sign_message(key_from_text(key), msg_hash=md)
    sig = b64decode(sig)

    # pycoin doesn't support segwit signing so we have to adjust the header
    if addr_fmt == AF_CLASSIC:
        adjust = 0
    elif addr_fmt == AF_P2WPKH_P2SH:
        adjust = 4
    elif addr_fmt == AF_P2WPKH:
        adjust = 8
    else:
        raise ValueError('unsupported address format for signing')

    if adjust:
        sig = bytes([sig[0] + adjust]) + sig[1:]

    if b64:
        return b64encode(sig)
    else:
        return sig

def detruncate_address(s):
    if s[0] == "↳":
        s = s[1:]
    start, end = s.split('⋯')
    return start, end

def seconds2human_readable(s):
    # duplicate from shared/utils.py - needed for tests
    days = s // (3600 * 24)
    hours = s % (3600 * 24) // 3600
    minutes = (s % 3600) // 60
    seconds = (s % 3600) % 60
    msg = []
    if days:
        msg.append("%dd" % days)
    if hours:
        msg.append("%dh" % hours)
    if minutes:
        msg.append("%dm" % minutes)
    if seconds:
        msg.append("%ds" % seconds)

    return " ".join(msg)

# EOF
