# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Address ownership tests.
#
import pytest, time, io, csv
from txn import fake_address
from base58 import encode_base58_checksum
from helpers import hash160, addr_from_display_format
from bip32 import BIP32Node
from constants import AF_P2WSH, AF_P2SH, AF_P2WSH_P2SH, AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH
from constants import simulator_fixed_xprv, simulator_fixed_tprv, addr_fmt_names
from charcodes import KEY_QR

@pytest.fixture
def wipe_cache(sim_exec):
    def doit():
        cmd = f'from ownership import OWNERSHIP; OWNERSHIP.wipe_all();'
        sim_exec(cmd)
    return doit


'''
    >>> [AF_P2WSH, AF_P2SH, AF_P2WSH_P2SH, AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH]
        [14,       8,       26,            1,          7,         19]
'''
@pytest.mark.parametrize('addr_fmt', [
    AF_P2WSH, AF_P2SH, AF_P2WSH_P2SH, AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH
])
@pytest.mark.parametrize('testnet', [ False, True] )
def test_negative(addr_fmt, testnet, sim_exec):
    # unit test, no UX
    addr = fake_address(addr_fmt, testnet)

    cmd = f'from ownership import OWNERSHIP; w,path=OWNERSHIP.search({addr!r}); '\
            'RV.write(repr([w.name, path]))'
    lst = sim_exec(cmd)

    assert 'Explained' in lst

@pytest.mark.parametrize('addr_fmt, testnet', [
	(AF_CLASSIC, True),
	(AF_CLASSIC, False),
	(AF_P2WPKH, True),
	(AF_P2WPKH, False),
	(AF_P2WPKH_P2SH, True),
	(AF_P2WPKH_P2SH, False),

    # multisig - testnet only
	(AF_P2WSH, True),
	(AF_P2SH, True),
	(AF_P2WSH_P2SH,True),
])
@pytest.mark.parametrize('offset', [ 3, 760] )
@pytest.mark.parametrize('subaccount', [ 0, 34] )
@pytest.mark.parametrize('change_idx', [ 0, 1] )
@pytest.mark.parametrize('from_empty', [ True, False] )
def test_positive(addr_fmt, offset, subaccount, testnet, from_empty, change_idx,
    sim_exec, wipe_cache, make_myself_wallet, use_testnet, goto_home, pick_menu_item,
    enter_number, press_cancel, settings_set, import_ms_wallet, clear_ms
):
    from bech32 import encode as bech32_encode

    # API/Unit test, limited UX

    if not testnet and addr_fmt in { AF_P2WSH, AF_P2SH, AF_P2WSH_P2SH }:
        # multisig jigs assume testnet
        raise pytest.skip('testnet only')

    use_testnet(testnet)
    if from_empty:
        wipe_cache()        # very different codepaths
        settings_set('accts', [])

    coin_type = 1 if testnet else 0

    if addr_fmt in { AF_P2WSH, AF_P2SH, AF_P2WSH_P2SH }:
        from test_multisig import make_ms_address, HARD
        M, N = 1, 3

        expect_name = f'search-test-{addr_fmt}'
        clear_ms()
        keys = import_ms_wallet(M, N, name=expect_name, accept=1, addr_fmt=addr_fmt_names[addr_fmt])

        # iffy: no cosigner index in this wallet, so indicated that w/ path_mapper
        addr, scriptPubKey, script, details = make_ms_address(M, keys,
                    is_change=change_idx, idx=offset, addr_fmt=addr_fmt, testnet=int(testnet),
                    path_mapper=lambda cosigner: [HARD(45), change_idx, offset])

        path = f'.../{change_idx}/{offset}'
    else:

        if addr_fmt == AF_CLASSIC:
            menu_item = expect_name = 'Classic P2PKH'
            path = "m/44h/{ct}h/{acc}h"
        elif addr_fmt == AF_P2WPKH_P2SH:
            menu_item = expect_name = 'P2SH-Segwit'
            path = "m/49h/{ct}h/{acc}h"
            clear_ms()
        elif addr_fmt == AF_P2WPKH:
            menu_item = expect_name = 'Segwit P2WPKH'
            path = "m/84h/{ct}h/{acc}h"
        else:
            raise ValueError(addr_fmt)

        path_prefix = path.format(ct=coin_type, acc=subaccount)
        path = path_prefix + f'/{change_idx}/{offset}'
        print(f'path = {path}')

        # see addr_vs_path
        mk = BIP32Node.from_wallet_key(simulator_fixed_tprv if testnet else simulator_fixed_xprv)
        sk = mk.subkey_for_path(path[2:].replace('h', "'"))

        if addr_fmt == AF_CLASSIC:
            addr = sk.address(netcode="XTN" if testnet else "BTC")
        elif addr_fmt == AF_P2WPKH_P2SH:
            pkh = sk.hash160()
            digest = hash160(b'\x00\x14' + pkh)
            addr = encode_base58_checksum(bytes([196 if testnet else 5]) + digest)
        else:
            pkh = sk.hash160()
            addr = bech32_encode('tb' if testnet else 'bc', 0, pkh)
    
        if subaccount:
            # need to hint we're doing a non-zero acccount number
            goto_home()
            settings_set('axskip', True)
            pick_menu_item('Address Explorer')
            pick_menu_item('Account Number')
            enter_number(subaccount)
            pick_menu_item(menu_item)
            press_cancel()

    cmd = f'from ownership import OWNERSHIP; w,path=OWNERSHIP.search({addr!r}); '\
            'RV.write(repr([w.name, path]))'
    lst = sim_exec(cmd)
    if 'candidates without finding a match' in lst:
        # some kinda timing issue, but don't want big delays, so just retry
        print("RETRY search!")
        lst = sim_exec(cmd)
        
    assert 'Traceback' not in lst, lst

    lst = eval(lst)
    assert len(lst) == 2

    got_name, got_path = lst
    assert expect_name in got_name
    if subaccount and '...' not in path:
        # not expected for multisig, since we have proper wallet name
        assert f'Account#{subaccount}' in got_name

    assert got_path == (change_idx, offset)

@pytest.mark.parametrize('valid', [ True, False] )
@pytest.mark.parametrize('testnet', [ True, False] )
@pytest.mark.parametrize('method', [ 'qr', 'nfc'] )
@pytest.mark.parametrize('multisig', [ True, False] )
def test_ux(valid, testnet, method,
    sim_exec, wipe_cache, make_myself_wallet, use_testnet, goto_home, pick_menu_item,
    press_cancel, press_select, settings_set, is_q1, nfc_write, need_keypress,
    cap_screen, cap_story, load_shared_mod, scan_a_qr, skip_if_useless_way,
    sign_msg_from_address, multisig, import_ms_wallet, clear_ms, verify_qr_address,
    src_root_dir, sim_root_dir
):
    skip_if_useless_way(method)
    addr_fmt = AF_CLASSIC

    if valid:
        if multisig:
            from test_multisig import make_ms_address, HARD
            M, N = 2, 3

            expect_name = f'own_ux_test'
            clear_ms()
            keys = import_ms_wallet(M, N, AF_P2WSH, name=expect_name, accept=1)

            # iffy: no cosigner index in this wallet, so indicated that w/ path_mapper
            addr, scriptPubKey, script, details = make_ms_address(
                M, keys, is_change=0, idx=50, addr_fmt=AF_P2WSH,
                testnet=int(testnet), path_mapper=lambda cosigner: [HARD(45), 0, 50]
            )
            addr_fmt = AF_P2WSH
        else:
            mk = BIP32Node.from_wallet_key(simulator_fixed_tprv if testnet else simulator_fixed_xprv)
            path = "m/44h/{ct}h/{acc}h/0/3".format(acc=0, ct=(1 if testnet else 0))
            sk = mk.subkey_for_path(path)
            addr = sk.address(netcode="XTN" if testnet else "BTC")
    else:
        addr = fake_address(addr_fmt, testnet)

    if method == 'qr':
        goto_home()
        pick_menu_item('Scan Any QR Code')
        scan_a_qr(addr)
        time.sleep(1)

        title, story = cap_story()

        assert addr == addr_from_display_format(story.split("\n\n")[0])
        assert '(1) to verify ownership' in story
        need_keypress('1')

    elif method == 'nfc':
        
        cc_ndef = load_shared_mod('cc_ndef', f'{src_root_dir}/shared/ndef.py')
        n = cc_ndef.ndefMaker()
        n.add_text(addr)
        ccfile = n.bytes()

        # run simulator w/ --set nfc=1 --eff
        goto_home()
        pick_menu_item('Advanced/Tools')
        pick_menu_item('NFC Tools')
        pick_menu_item('Verify Address')
        with open(f'{sim_root_dir}/debug/nfc-addr.ndef', 'wb') as f:
            f.write(ccfile)
        nfc_write(ccfile)
        #press_select()

    else:
        raise ValueError(method)

    time.sleep(1)
    title, story = cap_story()
    assert addr == addr_from_display_format(story.split("\n\n")[0])

    if title == 'Unknown Address' and not testnet:
        assert 'That address is not valid on Bitcoin Testnet' in story
    elif valid:
        assert title == ('Verified Address' if is_q1 else "Verified!")
        assert 'Found in wallet' in story
        assert 'Derivation path' in story

        if is_q1:
            # check it can display as QR from here
            need_keypress(KEY_QR)
            verify_qr_address(addr_fmt, addr)
            press_cancel()

        if multisig:
            assert expect_name in story
            assert "Press (0) to sign message with this key" not in story
        else:
            assert 'P2PKH' in story
            assert "Press (0) to sign message with this key" in story
            need_keypress('0')
            msg = "coinkite CC the most solid HWW"
            sign_msg_from_address(msg, addr, path, addr_fmt, method, testnet)

    else:
        assert title == 'Unknown Address'
        assert 'Searched ' in story
        assert 'candidates without finding a match' in story

@pytest.mark.parametrize("af", ["P2SH-Segwit", "Segwit P2WPKH", "Classic P2PKH", "ms0"])
def test_address_explorer_saver(af, wipe_cache, settings_set, goto_address_explorer,
                                pick_menu_item, need_keypress, sim_exec, clear_ms,
                                import_ms_wallet, press_select, goto_home, nfc_write,
                                load_shared_mod, load_export_and_verify_signature,
                                cap_story, is_q1, src_root_dir, sim_root_dir):
    goto_home()
    wipe_cache()
    settings_set('accts', [])

    if af == "ms0":
        clear_ms()
        import_ms_wallet(2,3, name=af)
        press_select()  # accept ms import

    goto_address_explorer()
    pick_menu_item(af)
    need_keypress("1")  # save to SD

    cmd = f'import os; RV.write(repr([i for i in os.listdir() if ".own" in i]))'
    lst = sim_exec(cmd)
    assert 'Traceback' not in lst, lst
    lst = eval(lst)
    assert lst

    if af == "ms0":
        return  # multisig addresses are blanked

    title, body = cap_story()
    contents, sig_addr, _ = load_export_and_verify_signature(body, "sd", label="Address summary")
    addr_dump = io.StringIO(contents)
    cc = csv.reader(addr_dump)
    hdr = next(cc)
    assert hdr == ['Index', 'Payment Address', 'Derivation']
    addr = None
    for n, (idx, addr, deriv) in enumerate(cc, start=0):
        assert int(idx) == n
        if idx == 200:
            addr = addr

    cc_ndef = load_shared_mod('cc_ndef', f'{src_root_dir}/shared/ndef.py')
    n = cc_ndef.ndefMaker()
    n.add_text(addr)
    ccfile = n.bytes()

    # run simulator w/ --set nfc=1 --eff
    goto_home()
    pick_menu_item('Advanced/Tools')
    pick_menu_item('NFC Tools')
    pick_menu_item('Verify Address')
    with open(f'{sim_root_dir}/debug/nfc-addr.ndef', 'wb') as f:
        f.write(ccfile)

    nfc_write(ccfile)

    time.sleep(1)
    title, story = cap_story()

    assert addr == addr_from_display_format(story.split("\n\n")[0])
    assert title == ('Verified Address' if is_q1 else "Verified!")
    assert 'Found in wallet' in story
    assert 'Derivation path' in story
    if af == "Segwit P2WPKH":
        assert " P2WPKH " in story
    else:
        assert af in story


def test_regtest_addr_on_mainnet(goto_home, is_q1, pick_menu_item, scan_a_qr, nfc_write, cap_story,
                                 need_keypress, load_shared_mod, use_mainnet, src_root_dir, sim_root_dir):
    # testing bug in chains.possible_address_fmt
    # allowed regtest addresses to be allowed on main chain
    goto_home()
    use_mainnet()
    addr = "bcrt1qmff7njttlp6tqtj0nq7svcj2p9takyqm3mfl06"
    if is_q1:
        pick_menu_item('Scan Any QR Code')
        scan_a_qr(addr)
        time.sleep(1)

        title, story = cap_story()

        assert addr == addr_from_display_format(story.split("\n\n")[0])
        assert '(1) to verify ownership' in story
        need_keypress('1')

    else:
        cc_ndef = load_shared_mod('cc_ndef', f'{src_root_dir}/shared/ndef.py')
        n = cc_ndef.ndefMaker()
        n.add_text(addr)
        ccfile = n.bytes()

        # run simulator w/ --set nfc=1 --eff
        pick_menu_item('Advanced/Tools')
        pick_menu_item('NFC Tools')
        pick_menu_item('Verify Address')
        with open(f'{sim_root_dir}/debug/nfc-addr.ndef', 'wb') as f:
            f.write(ccfile)
        nfc_write(ccfile)
        # press_select()

    time.sleep(1)
    title, story = cap_story()
    assert addr == addr_from_display_format(story.split("\n\n")[0])

    assert title == 'Unknown Address'
    assert "not valid on Bitcoin Mainnet" in story

# EOF
