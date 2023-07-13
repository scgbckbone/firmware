# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# flow.py - Menu structure
#
from menu import MenuItem, ToggleMenuItem
from glob import settings

from actions import *
from choosers import *
from mk4 import dev_enable_repl
from multisig import make_multisig_menu, import_multisig_nfc
from seed import make_ephemeral_seed_menu
from address_explorer import address_explore
from users import make_users_menu
from drv_entro import drv_entro_start, password_entry
from backups import clone_start, clone_write_data
from xor_seed import xor_split_start, xor_restore_start
from countdowns import countdown_chooser
from hsm import hsm_policy_available
from paper import make_paper_wallet
from trick_pins import TrickPinMenu


trick_pin_menu = TrickPinMenu.make_menu

#
# NOTE: "Always In Title Case"
#
# - try to keep harmless things as first item: so double-tap of OK does no harm

#
# Predicates
#

def has_secrets():
    from pincodes import pa
    return not pa.is_secret_blank()

def nfc_enabled():
    from glob import NFC
    return bool(NFC)

def vdisk_enabled():
    return bool(settings.get('vidsk', 0))

def se2_and_real_secret():
    from pincodes import pa
    return (not pa.is_secret_blank()) and (not pa.tmp_value)


HWTogglesMenu = [
    ToggleMenuItem('USB Port', 'du', ['Default On', 'Disable USB'], invert=True,
        on_change=change_usb_disable, story='''\
Blocks any data over USB port. Useful when your plan is air-gap usage.'''),
    ToggleMenuItem('Virtual Disk', 'vidsk', ['Default Off', 'Enable', 'Enable & Auto'],
        on_change=change_virtdisk_enable,
        story='''Coldcard can emulate a virtual disk drive (4MB) where new PSBT files \
can be saved. Signed PSBT files (transactions) will also be saved here. \n\
In "auto" mode, selects PSBT as soon as written.'''),
    ToggleMenuItem('NFC Sharing', 'nfc', ['Default Off', 'Enable NFC'], on_change=change_nfc_enable,
        story='''\
NFC (Near Field Communications) allows a phone to "tap" to send and receive data \
with the Coldcard.''',
        predicate=lambda: version.has_nfc),
]

# all pre-login values
LoginPrefsMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem('Change Main PIN', f=pin_changer, arg='main'),
    MenuItem('Trick PINs', menu=trick_pin_menu),
    MenuItem('Set Nickname', f=pick_nickname),
    MenuItem('Scramble Keypad', f=pick_scramble),
    MenuItem('Kill Key', f=pick_killkey),
    MenuItem('Login Countdown', chooser=countdown_chooser),
    MenuItem('MicroSD 2FA', menu=microsd_2fa, predicate=se2_and_real_secret),
    MenuItem('Test Login Now', f=login_now, arg=1),
]

SettingsMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem('Login Settings', menu=LoginPrefsMenu),
    MenuItem('Hardware On/Off', menu=HWTogglesMenu),
    MenuItem('Multisig Wallets', menu=make_multisig_menu),
    MenuItem('Display Units', chooser=value_resolution_chooser),
    MenuItem('Max Network Fee', chooser=max_fee_chooser),
    MenuItem('Idle Timeout', chooser=idle_timeout_chooser),
    ToggleMenuItem('Delete PSBTs', 'del', ['Default Keep', 'Delete PSBTs'],
        story='''\
PSBT files (on SDCard) will be blanked & deleted after they are used. \
The signed transaction will be named <TXID>.txn, so the file name does not leak information.

MS-DOS tools should not be able to find the PSBT data (ie. undelete), but forensic tools \
which take apart the flash chips of the SDCard may still be able to find the \
data or filenames.'''),
    ToggleMenuItem('Menu Wrapping', 'wa', ['Default Off', 'Enable'],
           story='''When enabled, allows scrolling past menu top/bottom \
(wrap around). By default, this is only happens in very large menus.'''),
    ToggleMenuItem('Keyboard EMU', 'emu', ['Default Off', 'Enable'],
           on_change=usb_keyboard_emulation,
           predicate=has_secrets,  # cannot generate BIP85 passwords without secret
           story='''This mode adds a top-level menu item for typing \
deterministically-generated passwords (BIP-85), directly into an \
attached USB computer (as an emulated keyboard).'''),
]

XpubExportMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem("Segwit (BIP-84)", f=export_xpub, arg=84),
    MenuItem("Classic (BIP-44)", f=export_xpub, arg=44),
    MenuItem("P2WPKH/P2SH (49)", f=export_xpub, arg=49),
    MenuItem("Master XPUB", f=export_xpub, arg=0),
    MenuItem("Current XFP", f=export_xpub, arg=-1),
]

WalletExportMenu = [  
    #         xxxxxxxxxxxxxxxx
    MenuItem("Bitcoin Core", f=bitcoin_core_skeleton),
    MenuItem("Sparrow Wallet", f=named_generic_skeleton, arg="Sparrow"),
    MenuItem("Electrum Wallet", f=electrum_skeleton),
    MenuItem("Wasabi Wallet", f=wasabi_skeleton),
    MenuItem("Unchained", f=unchained_capital_export),
    MenuItem("Lily Wallet", f=named_generic_skeleton, arg="Lily"),
    MenuItem("Samourai Postmix", f=samourai_post_mix_descriptor_export),
    MenuItem("Samourai Premix", f=samourai_pre_mix_descriptor_export),
    # MenuItem("Samourai BadBank", f=samourai_bad_bank_descriptor_export),  # not released yet
    MenuItem("Descriptor", f=ss_descriptor_skeleton),
    MenuItem("Generic JSON", f=generic_skeleton),
    MenuItem("Export XPUB", menu=XpubExportMenu),
    MenuItem("Dump Summary", predicate=has_secrets, f=dump_summary),
]

# useful even if no secrets, may operate on VDisk or SDCard when inserted
FileMgmtMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem("Verify Backup", f=verify_backup),
    MenuItem("Backup System", predicate=has_secrets, f=backup_everything),
    MenuItem('Export Wallet', predicate=has_secrets, menu=WalletExportMenu),        #dup elsewhere
    MenuItem('Sign Text File', predicate=has_secrets, f=sign_message_on_sd),
    MenuItem('Batch Sign PSBT', predicate=has_secrets, f=batch_sign),
    MenuItem('List Files', f=list_files),
    MenuItem('Verify Sig File', f=verify_sig_file),
    MenuItem('NFC File Share', predicate=nfc_enabled, f=nfc_share_file),
    MenuItem('Clone Coldcard', predicate=has_secrets, f=clone_write_data),
    MenuItem('Format SD Card', f=wipe_sd_card),
    MenuItem('Format RAM Disk', predicate=vdisk_enabled, f=wipe_vdisk),
]

UpgradeMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem('Show Version', f=show_version),
    MenuItem('From MicroSD', f=microsd_upgrade, arg=False),
    MenuItem('From VirtDisk', predicate=vdisk_enabled, f=microsd_upgrade, arg=True),  # force_vdisk=True
    MenuItem('Bless Firmware', f=bless_flash),
]

DevelopersMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem("Serial REPL", f=dev_enable_repl),
    MenuItem("Wipe LFS", f=wipe_filesystem),                # kills settings, HSM stuff
    MenuItem('Warm Reset', f=reset_self),
    MenuItem("Restore Txt Bkup", f=restore_everything_cleartext),
]

AdvancedVirginMenu = [                  # No PIN, no secrets yet (factory fresh)
    #         xxxxxxxxxxxxxxxx
    MenuItem("View Identity", f=view_ident),
    MenuItem("Ephemeral Seed", menu=make_ephemeral_seed_menu),
    MenuItem('Upgrade Firmware', menu=UpgradeMenu),
    MenuItem('Paper Wallets', f=make_paper_wallet, predicate=lambda: make_paper_wallet),
    MenuItem('Perform Selftest', f=start_selftest),
    MenuItem('Secure Logout', f=logout_now),
]

AdvancedPinnedVirginMenu = [            # Has PIN but no secrets yet
    #         xxxxxxxxxxxxxxxx
    MenuItem("View Identity", f=view_ident),
    MenuItem("Ephemeral Seed", menu=make_ephemeral_seed_menu),
    MenuItem("Upgrade Firmware", menu=UpgradeMenu),
    MenuItem("File Management", menu=FileMgmtMenu),
    MenuItem('Paper Wallets', f=make_paper_wallet, predicate=lambda: make_paper_wallet),
    MenuItem('Perform Selftest', f=start_selftest),
    MenuItem("I Am Developer.", menu=maybe_dev_menu),
    MenuItem('Secure Logout', f=logout_now),
]

DebugFunctionsMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem('Debug: assert', f=debug_assert),
    MenuItem('Debug: except', f=debug_except),
    MenuItem('Check: BL FW', f=check_firewall_read),
    MenuItem('Warm Reset', f=reset_self),
    #MenuItem("Perform Selftest", f=start_selftest),
]

SeedXORMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem("Split Existing", f=xor_split_start, predicate=lambda: settings.get('words', True)),
    MenuItem("Restore Seed XOR", f=xor_restore_start),
]

SeedFunctionsMenu = [
    MenuItem('View Seed Words', f=view_seed_words),     # text is a little wrong sometimes, rare
    MenuItem('Seed XOR', menu=SeedXORMenu),
    MenuItem("Destroy Seed", f=clear_seed),
    MenuItem('Lock Down Seed', f=convert_bip39_to_bip32),
]

DangerZoneMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem("Debug Functions", menu=DebugFunctionsMenu),       # actually harmless
    MenuItem("Seed Functions", menu=SeedFunctionsMenu),
    MenuItem("I Am Developer.", menu=maybe_dev_menu),
    MenuItem('Perform Selftest', f=start_selftest),             # little harmful
    MenuItem("Set High-Water", f=set_highwater),
    MenuItem('Wipe HSM Policy', f=wipe_hsm_policy, predicate=hsm_policy_available),
    MenuItem('Clear OV cache', f=wipe_ovc),
    ToggleMenuItem("Sighash Checks", "sighshchk", ["Default: Block", "Warn"], invert=True,
                   story='''\
If you disable sighash flag restrictions, and ignore the \
warnings, funds can be stolen by specially crafted PSBT or MitM.

Keep blocked unless you intend to sign special transactions.'''),
    ToggleMenuItem('Testnet Mode', 'chain', ['Bitcoin', 'Testnet3', 'Regtest'],
        value_map=['BTC', 'XTN', 'XRT'],
        on_change=change_which_chain,
        story="Testnet must only be used by developers because \
correctly- crafted transactions signed on Testnet could be broadcast on Mainnet."),
    MenuItem('Settings Space', f=show_settings_space),
    MenuItem('MCU Key Slots', f=show_mcu_keys_left),
]

BackupStuffMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem("Backup System", f=backup_everything),
    MenuItem("Verify Backup", f=verify_backup),
    MenuItem("Restore Backup", f=restore_everything),   # just a redirect really
    MenuItem('Clone Coldcard', predicate=has_secrets, f=clone_write_data),
]

NFCToolsMenu = [
    MenuItem('Show Address', f=nfc_show_address),
    MenuItem('Sign Message', f=nfc_sign_msg),
    MenuItem('Verify Sig File', f=nfc_sign_verify),
    MenuItem('File Share', f=nfc_share_file),
    MenuItem('Import Multisig', f=import_multisig_nfc),
]

AdvancedNormalMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem("Backup", menu=BackupStuffMenu),
    MenuItem('Export Wallet', predicate=has_secrets, menu=WalletExportMenu),  # also inside FileMgmt
    MenuItem("Upgrade Firmware", menu=UpgradeMenu),
    MenuItem("File Management", menu=FileMgmtMenu),
    MenuItem('Derive Seed B85', f=drv_entro_start),
    MenuItem("View Identity", f=view_ident),
    MenuItem("Ephemeral Seed", menu=make_ephemeral_seed_menu),
    MenuItem('Paper Wallets', f=make_paper_wallet, predicate=lambda: make_paper_wallet),
    ToggleMenuItem('Enable HSM', 'hsmcmd', ['Default Off', 'Enable'],
                   story="Enable HSM? Enables all user management commands, and other HSM-only USB commands. \
By default these commands are disabled."),
    MenuItem('User Management', menu=make_users_menu),
    MenuItem('NFC Tools', predicate=nfc_enabled, menu=NFCToolsMenu),
    MenuItem("Danger Zone", menu=DangerZoneMenu),
]

# needs to create main wallet PIN
VirginSystem = [
    #         xxxxxxxxxxxxxxxx
    MenuItem('Choose PIN Code', f=initial_pin_setup),
    MenuItem('Advanced/Tools', menu=AdvancedVirginMenu),
    MenuItem('Bag Number', f=show_bag_number),
    MenuItem('Help', f=virgin_help),
]

ImportWallet = [
    #         xxxxxxxxxxxxxxxx
    MenuItem("24 Words", menu=start_seed_import, arg=24),
    MenuItem("18 Words", menu=start_seed_import, arg=18),
    MenuItem("12 Words", menu=start_seed_import, arg=12),
    MenuItem("Restore Backup", f=restore_everything),
    MenuItem("Clone Coldcard", menu=clone_start),
    MenuItem("Import XPRV", f=import_xprv, arg=False),  # ephemeral=False
    MenuItem("Tapsigner Backup", f=import_tapsigner_backup_file, arg=False),
    MenuItem("Seed XOR", f=xor_restore_start),
]

NewSeedMenu = [
    #         xxxxxxxxxxxxxxxx
    MenuItem("24 Word (default)", f=pick_new_seed, arg=24),
    MenuItem("12 Word", f=pick_new_seed, arg=12),
    MenuItem("24 Word Dice Roll", f=new_from_dice, arg=24),
    MenuItem("12 Word Dice Roll", f=new_from_dice, arg=12),
]

# has PIN, but no secret seed yet
EmptyWallet = [
    #         xxxxxxxxxxxxxxxx
    MenuItem('New Seed Words', menu=NewSeedMenu),
    MenuItem('Import Existing', menu=ImportWallet),
    MenuItem('Help', f=virgin_help),
    MenuItem('Advanced/Tools', menu=AdvancedPinnedVirginMenu),
    MenuItem('Settings', menu=SettingsMenu),
]

# In operation, normal system, after a good PIN received.
NormalSystem = [
    #         xxxxxxxxxxxxxxxx
    MenuItem('Ready To Sign', f=ready2sign),
    MenuItem('Passphrase', f=start_b39_pw, predicate=lambda: settings.get('words', True)),
    MenuItem('Start HSM Mode', f=start_hsm_menu_item, predicate=hsm_policy_available),
    MenuItem("Address Explorer", f=address_explore),
    MenuItem('Type Passwords', f=password_entry, predicate=lambda: settings.get("emu", False) and has_secrets()),
    MenuItem('Secure Logout', f=logout_now),
    MenuItem('Advanced/Tools', menu=AdvancedNormalMenu),
    MenuItem('Settings', menu=SettingsMenu),
]

# Shown until unit is put into a numbered bag
FactoryMenu = [
    MenuItem('Bag Me Now'),     # nice to have NOP at top of menu
    MenuItem('DFU Upgrade', f=start_dfu),
    MenuItem('Show Version', f=show_version),
    MenuItem('Ship W/O Bag', f=ship_wo_bag),
    MenuItem("Debug Functions", menu=DebugFunctionsMenu),
    MenuItem("Perform Selftest", f=start_selftest),
]
