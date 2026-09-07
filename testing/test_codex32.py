# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.

import pytest


CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'

SHARES = [
    'MS12NAMEA320ZYXWVUTSRQPNMLKJHGFEDCAXRPP870HKKQRM',
    'ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyq'
    '9dsuypw2ragmel',
    'ms10testsqqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0j'
    'qgfzyvjz2f389q5j52ev95hz7vp3xgengdfkxuurjw3m8s7nu0ax3uvrcss9'
    'ddwnst',
    'CC100C8VSM32ZXFGUHPCHTLUPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZY'
    'GSFJD6AN074RXVCEMLH8WU3TK925ACDEFGHJKLMNPQRSTUVWXY06GTQ0CGV2S'
    'NQHVLX3',
]


def native_encoding(value):
    # Independent implementation of the 72-byte storage envelope.
    value = value.lower()
    hrp, encoded = value.split('1')
    checksum_len = 15 if len(value) == 127 else 13
    body = encoded[:-checksum_len]
    values = [CHARSET.index(ch) for ch in body]

    accumulator = 0
    bits = 0
    packed = bytearray()
    for item in values:
        accumulator = (accumulator << 5) | item
        bits += 5
        while bits >= 8:
            bits -= 8
            packed.append((accumulator >> bits) & 0xff)
            accumulator &= (1 << bits) - 1
    if bits:
        packed.append(accumulator << (8 - bits))

    size_code = {48: 0, 74: 1, 127: 2}[len(value)]
    flags = size_code | (4 if hrp == 'cc' else 0)
    return bytes([2, flags]) + bytes(packed)


@pytest.mark.parametrize('share', SHARES)
def test_native_secret_survives_settings_and_backup(
        share, set_encoded_secret, sim_exec, settings_get, settings_set, get_secrets):
    encoded = native_encoding(share)
    expected = encoded.ljust(72, b'\0')
    set_encoded_secret(encoded)

    assert settings_get('_c32') == 1
    command = (
        'from pincodes import pa; from stash import SecretStash; '
        'RV.write(SecretStash.decode_codex32(pa.fetch()).to_string())')
    assert sim_exec(command) == share.lower()

    backup_hex = get_secrets()['raw_secret']
    if len(backup_hex) % 2:
        backup_hex += '0'
    assert bytes.fromhex(backup_hex).ljust(72, b'\0') == expected

    # This setting is only a menu hint; losing it cannot lose share data.
    settings_set('_c32', None)
    assert sim_exec(command) == share.lower()


def test_qr_decoder_accepts_codex32(sim_exec, only_q1):
    share = SHARES[1]
    result = sim_exec(
        "from decoders import decode_secret; RV.write(repr(decode_secret(%r)))" % share)
    assert eval(result) == ('codex32', share)
