# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.

from codex32 import SECRET, Share, generate_share
from stash import SecretStash
from ubinascii import hexlify as b2a_hex
from utils import deserialize_secret


# BIP-93 vectors, including interpolation and both checksum lengths.
s = Share.parse('ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlw')
assert s.threshold == 0
assert s.index == SECRET
assert b2a_hex(s.to_seed()) == b'318c6318c6318c6318c6318c6318c631'

sa = Share.parse('MS12NAMEA320ZYXWVUTSRQPNMLKJHGFEDCAXRPP870HKKQRM')
sc = Share.parse('MS12NAMECACDEFGHJKLMNPQRSTUVWXYZ023FTR2GDZMPY6PN')
sd = generate_share([sa, sc], 'd')
ss = generate_share([sa, sc, sd], SECRET)
assert b2a_hex(ss.to_seed()) == b'd1808e096b35b209ca12132b264662a5'

long_ms = Share.parse(
    'ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyq'
    '9dsuypw2ragmel')
long_cc = Share.parse(
    'CC100C8VSM32ZXFGUHPCHTLUPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZY'
    'GSFJD6AN074RXVCEMLH8WU3TK925ACDEFGHJKLMNPQRSTUVWXY06GTQ0CGV2S'
    'NQHVLX3')

# The complete data section, including otherwise-lost trailing bits, survives
# the 72-byte secret format for secret and non-secret shares.
for original in (s, sa, long_ms, long_cc):
    encoded = SecretStash.encode(codex32=original)
    assert len(encoded) == 72
    assert SecretStash.is_codex32(encoded)
    assert deserialize_secret(SecretStash.storage_serialize(encoded)) == encoded

    restored = SecretStash.decode_codex32(encoded)
    assert restored.to_string() == original.to_string()

    mode, raw, node = SecretStash.decode(encoded)
    assert raw == original.to_seed()
    assert mode == ('xprv' if original.hrp == 'cc' else 'master')
    node.blank()

# Demonstrate why retaining only seed bytes is insufficient for arbitrary
# interpolated Codex32 shares.
seed, pad = long_ms.to_seed_and_pad()
assert pad
assert Share.from_seed(seed, long_ms.hrp, long_ms.uid, long_ms.index,
                       long_ms.threshold).to_string() != long_ms.to_string()
assert Share.from_seed(seed, long_ms.hrp, long_ms.uid, long_ms.index,
                       long_ms.threshold, pad).to_string() == long_ms.to_string()

print('Codex32: OK')
