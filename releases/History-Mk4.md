*See ChangeLog.md for more recent changes, these are historic versions*

## 5.4.2 - 2025-04-16

- Huge new feature: CCC - ColdCard Cosign
    - COLDCARD holds a key in a 2-of-3 multisig, in addition to the normal signing key it has.
    - it applies a spending policy like an HSM:
        - velocity and magnitude limits
        - whitelisted destination addresses
        - 2FA authentication using phone app ([RFC 6238](https://www.rfc-editor.org/rfc/rfc6238))
    - but will sign its part of a transaction automatically if those condition are met, 
      giving you 2 keys of the multisig and control over the funds
    - spending policy can be exceeded with help of the other co-signer (3rd key), when needed
    - cannot view or change the CCC spending policy once set, policy violations are not explained
    - existing multisig wallets can be used by importing the spending-policy-controlled key
- New Feature: Multisig transactions are finalized. Allows use of [PushTX](https://pushtx.org/)
  with multisig wallets.  Read more [here](https://github.com/Coldcard/firmware/blob/master/docs/limitations.md#p2sh--multisig)
- New Feature: Signing artifacts re-export to various media. Now you have the option of
  exporting the signing products (transaction/PSBT) to different media than the original source.
  Incoming PSBT over QR can be signed and saved to SD card if desired.
- New Feature: Multisig export files are signed now. Read more [here](https://github.com/Coldcard/firmware/blob/master/docs/msg-signing.md#signed-exports)
- Enhancement: NFC export usability upgrade: NFC keeps exporting until CANCEL/X is pressed
- Enhancement: Add `Bitcoin Safe` option to `Export Wallet`
- Enhancement: 10% performance improvement in USB upload speed for large files
- Bugfix: Do not allow change Main PIN to same value already used as Trick PIN, even if
  Trick PIN is hidden.
- Bugfix: Fix stuck progress bar under `Receiving...` after a USB communications failure
- Bugfix: Showing derivation path in Address Explorer for root key (m) showed double slash (//)
- Bugfix: Can restore developer backup with custom password other than 12 words format
- Bugfix: Virtual Disk auto mode ignores already signed PSBTs (with "-signed" in file name)
- Bugfix: Virtual Disk auto mode stuck on "Reading..." screen sometimes
- Bugfix: Finalization of foreign inputs from partial signatures. Thanks Christian Uebber
- Bugfix: Temporary seed from COLDCARD backup failed to load stored multisig wallets
- Change: `Destroy Seed` also removes all Trick PINs from SE2.
- Change: `Lock Down Seed` requires pressing confirm key (4) to execute

## 5.4.1 - 2025-02-13

- New signing features:
    - Sign message from note text, or password note
    - JSON message signing. Use JSON object to pass data to sign in form
        `{"msg":"<required msg>","subpath":"<optional sp>","addr_fmt": "<optional af>"}`
    - Sign message with key resulting from positive ownership check. Press (0) and
      enter or scan message text to be signed.
    - Sign message with key selected from Address Explorer Custom Path menu. Press (2) and
      enter or scan message text to be signed.
- Enhancement: New address display format improves address verification on screen (groups of 4).
- Deltamode enhancements:
    - Hide Secure Notes & Passwords in Deltamode. Wipe seed if notes menu accessed. 
    - Hide Seed Vault in Deltamode. Wipe seed if Seed Vault menu accessed. 
    - Catch more DeltaMode cases in XOR submenus. Thanks [@dmonakhov](https://github.com/dmonakhov)
- Enhancement: Add ability to switch between BIP-32 xpub, and obsolete SLIP-132 format
  in `Export XPUB`
- Enhancement: Use the fact that master seed cannot be used as ephemeral seed, to show message 
  about successful master seed verification.
- Enhancement: Allow devs to override backup password.
- Enhancement: Add option to show/export full multisg addresses without censorship. Enable
  in `Settings > Multisig Wallets > Full Address View`.
- Enhancement: If derivation path is omitted during message signing, derivation path
  default is no longer root (m), instead it is based on requested address format
  (`m/44h/0h/0h/0/0` for p2pkh, and `m/84h/0h/0h/0/0` for p2wpkh). Conversely,
  if address format is not provided but subpath derivation starts with:
  `m/84h/...` or `m/49h/...`, then p2wpkh or p2sh-p2wpkh respectively, is used.
- Bugfix: Sometimes see a struck screen after _Verifying..._ in boot up sequence.
  On Q, result is blank screen, on Mk4, result is three-dots screen.
- Bugfix: Do not allow to enable/disable Seed Vault feature when in temporary seed mode.
- Bugfix: Bless Firmware causes hanging progress bar.
- Bugfix: Prevent yikes in ownership search.
- Bugfix: Factory-disabled NFC was not recognized correctly.
- Bugfix: Be more robust about flash filesystem holding the settings.
- Bugfix: Do not include sighash in PSBT input data, if sighash value is `SIGHASH_ALL`.
- Bugfix: Allow import of multisig descriptor with root (m) keys in it.
  Thanks [@turkycat](https://github.com/turkycat)
- Change: Do not purge settings of current active tmp seed when deleting it from Seed Vault.
- Change: Rename Testnet3 -> Testnet4 (all parameters unchanged).
- Mk4 Specific Change:
  - Enhancement: Export single sig descriptor with simple QR.


## 5.4.0 - 2024-09-12

- New Feature: Opt-in support for unsorted multisig, which ignores BIP-67 policy. Use
  descriptor with `multi(...)`. Disabled by default, Enable in 
  `Settings > Multisig Wallets > Legacy Multisig`. Recommended for existing multisig
  wallets, not new ones.
- New Feature: Named multisig descriptor imports. Wrap descriptor in json:
    `{"name:"ms0", "desc":"<descriptor>"}` to provide a name for the menu in `name`.
  instead of the filename. Most useful for USB and NFC imports which have no filename, 
  (name is created from descriptor checksum in those cases).
- New Feature: XOR from Seed Vault (select other parts of the XOR from seeds in the vault).
- Enhancement: upgrade to latest 
  [libsecp256k1: 0.5.0](https://github.com/bitcoin-core/secp256k1/releases/tag/v0.5.0) 
- Enhancement: Signature grinding optimizations. Now about 30% faster signing!
- Enhancement: Improve side-channel protection: libsecp256k1 context randomization now happens
  before each signing session.
- Enhancement: Allow JSON files in `NFC File Share`.
- Change: Do not require descriptor checksum when importing multisig wallets.
- Bugfix: Do not allow import of multisig wallet when same keys are shuffled.
- Bugfix: Do not read whole PSBT into memory when writing finalized transaction (performance).
- Bugfix: Prevent user from restoring Seed XOR when number of parts is smaller than 2.
- Bugfix: Fix display alignment of Seed Vault menu.
- Bugfix: Properly handle null data in `OP_RETURN`.
- Bugfix: Do not allow lateral scroll in Address Explorer when showing single address
  from custom path.
- Change: Remove Lamp Test from Debug Options (covered by selftest).
- Shared enhancements and fixes listed above.
- Bugfix: Correct intermittent card inserted/not inserted detection error.


## 5.3.3 - 2024-07-05

- New Feature: PushTX: once enabled with a service provider's URL, you can tap the COLDCARD
  and your phone will open a webpage that transmits your freshly-signed transaction onto
  the blockchain. See `Settings > NFC Push Tx` to enable and select service provider, or your
  own webpage. More at <https://pushtx.org>. You can also use this to broadcast any
  transaction found on the MicroSD card (See `Tools > NFC Tools > Push Transaction`).
- New Feature: Transaction Output Explorer: allows viewing all output details for
  larger txn (10+ output, 20+ change) before signing. Offered for large transactions only
  because we are already showing all the details for typical transactions.
- New Feature: Setting to enable always showing XFP as first item in home menu.
- Enhancement: When signing, show sum of outgoing value at top. Always show number
  of inputs/outputs and total change value.
- Enhancement: Add `Sign PSBT` shortcut to `NFC Tools` menu
- Enhancement: Stricter p2sh-p2wpkh validation checks.
- Enhancement: Show master XFP of BIP-85 derived wallet in story before activation. Only
  words and extended private key cases.
- Enhancement: Add `Theya` option to `Export Wallet`
- Enhancement: Mention the need to remove old duress wallets before locking down temporary seed.
- Bugfix: Fix PSBTv2 `PSBT_GLOBAL_TX_MODIFIABLE` parsing.
- Bugfix: Decrypting Tapsigner backup failed even for correct key.
- Bugfix: Clear any pending keystrokes before PSBT approval screen.
- Bugfix: Display max 20 change outputs in when signing, and max 10 of largest outputs, and
  offer the Transaction Output Explorer if more to be seen.
- Bugfix: Calculate progress bar correctly in Address Explorer after first page.
- Bugfix: Search also Wrapped Segwit single sig addresses if P2SH address provided, not just
  multisig (multisig has precedence for P2SH addresses)
- Bugfix: Address search would not find addresses for non-zero account numbers that had
  been exported but not yet seen in a PSBT.
- (v5.3.3/1.2.3Q) Bugfix: Trying to set custom URL for NFC push transaction caused yikes error.

- Bugfix: Displaying change address in Address Explorer fails if NFC and Vdisk not enabled.
- Bugfix: Fix yikes displaying BIP-85 WIF when both NFC and VDisk are disabled.
- Bugfix: Fix inability to export change addresses when both NFC and Vdisk are disabled.
- Bugfix: In BIP-39 words menu, show space character rather than Nokia-style placeholder
  which could be confused for an underscore (reported by `tobo@600.wtf`).


## 5.3.3 - 2024-07-05

- Bugfix: Trying to set custom URL for NFC push transaction caused yikes error.
- Bugfix: Displaying change address in Address Explorer fails if NFC and Vdisk not enabled.
- Bugfix: Fix yikes displaying BIP-85 WIF when both NFC and VDisk are disabled.
- Bugfix: Fix inability to export change addresses when both NFC and Vdisk are disabled.
- Bugfix: In BIP-39 words menu, show space character rather than Nokia-style placeholder
  which could be confused for an underscore (report by `tobo@600.wtf`).

## 5.3.2 - 2024-06-26

- New Feature: PushTX: once enabled with a service provider's URL, you can tap the COLDCARD
  and your phone will open a webpage that transmits your freshly-signed transaction onto
  the blockchain. See `Settings > NFC Push Tx` to enable and select service provider, or your
  own webpage. More at <https://pushtx.org>. You can also use this to broadcast any
  transaction found on the MicroSD card (See `Tools > NFC Tools > Push Transaction`).
- New Feature: Transaction Output Explorer: allows viewing all output details for
  larger txn (10+ output, 20+ change) before signing. Offered for large transactions only
  because we are already showing all the details for typical transactions.
- New Feature: Setting to enable always showing XFP as first item in home menu.
- Enhancement: When signing, show sum of outgoing value at top. Always show number
  of inputs/outputs and total change value.
- Enhancement: Add `Sign PSBT` shortcut to `NFC Tools` menu
- Enhancement: Stricter p2sh-p2wpkh validation checks.
- Enhancement: Show master XFP of BIP-85 derived wallet in story before activation. Only
  words and extended private key cases.
- Enhancement: Add `Theya` option to `Export Wallet`
- Enhancement: Mention the need to remove old duress wallets before locking down temporary seed.
- Bugfix: Fix PSBTv2 `PSBT_GLOBAL_TX_MODIFIABLE` parsing.
- Bugfix: Decrypting Tapsigner backup failed even for correct key.
- Bugfix: Clear any pending keystrokes before PSBT approval screen.
- Bugfix: Display max 20 change outputs in when signing, and max 10 of largest outputs, and
  offer the Transaction Output Explorer if more to be seen.
- Bugfix: Calculate progress bar correctly in Address Explorer after first page.
- Bugfix: Search also Wrapped Segwit single sig addresses if P2SH address provided, not just
  multisig (multisig has precedence for P2SH addresses)
- Bugfix: Address search would not find addresses for non-zero account numbers that had
  been exported but not yet seen in a PSBT.



## 5.3.1 - 2024-05-09

- _Important Bugfix_: Already imported multisig wallets would show errors when signing. This
  was caused by our internal change in key path notation from `84'` (prime) to `84h` (hardened).
- Enhancement: Add `Nunchuk` and `Zeus` options to `Export Wallet`
- Enhancement: `View Identity` shows temporary seed active at the top
- Enhancement: Can specify start index for address explorer export and browsing
- Enhancement: Allow unlimited index for BIP-85 derivations. Must be enabled first in `Danger Zone` 
- Change: `Passphrase` menu item is no longer offered if BIP39 passphrase
  already in use. Use `Restore Master` with ability to keep or purge current
  passphrase wallet settings.
- Change: Removed ability to add passphrase to master seed if active temporary seed.
- Change: Wipe LFS during `Lock Down Seed` and `Destroy Seed`
- Bugfix: Do not allow non-ascii or ascii non-printable characters in multisig wallet name
- Bugfix: `Brick Me` option for `If Wrong` PIN caused yikes.
- Bugfix: Properly handle and finalize framing error response in USB protocol.
- Bugfix: Handle ZeroSecretException for BIP39 passphrase calculation when on temporary
  seed without master secret
- Bugfix: Saving passphrase on SD Card caused a freeze that required reboot
- Bugfix: Properly verify signed armored message with regtest address
- Bugfix: Create ownership file when generating addresses export CSV
- Recovery SD Card image building moved into its own repo:
  [github.com/Coldcard/recovery-images](https://github.com/Coldcard/recovery-images)
- Bugfix: Reload trick pins before checking for active duress wallet.

- Enhancement: When providing 12 or 18 word seed phrase, valid final word choices
  are presented in a new menu.
- Enhancement: Move dice rolls (for generating master seed) to `Advanced` submenu.
- Enhancement: Using "Verify Address" in NFC Tools menu, allows entry of a payment address
  and reports if it is part of a wallet this Coldcard knows the key for. Includes Multisig
  and single sig wallets.
    - searches up to the first 1528 addresses (external and change addresses)
    - stores data as it goes to accelerate future uses
    - worst case, it can take up to 2 minutes to rule out an address, but after that it is fast!
- Bugfix: Constant `AFC_BECH32M` incorrectly set `AFC_WRAPPED` and `AFC_BECH32`.
- Bugfix: Fix inability to activate Duress Wallet as temporary seed when master seed is 12 words.
- Bugfix: Yikes when using BIP39 passphrase with temporary seed without master seed set.
- Bugfix: v1 and v2 QRs too small and not readable (fixed)
- Bugfix: Show indexes for full range of addresses we are able to generate during QR display.
- Tweak: Force default HW settings (USB,NFC,VDisk OFF) after clone/backup is restored.
- Tweak: Cleanup in NFC code: repeated messages, "Unable to find data expectd in NDEF", removed.
- Tweak: Function button change from (6) to (0) to view change addresses in `Address Explorer`
- Tweak: Function button change from (2) to (0) to switch to derived secret in `Derive Seed B85`
- Bootrom version bump: 3.2.0 released with no functional changes except those shared with Q.

## 5.2.2 - 2023-12-21

- Bugfix: Re-enable `Lock Down Seed` feature which was disabled by accident

## 5.2.1 - 2023-12-19

- New Feature: Temporary Seed import from a COLDCARD encrypted backup.
- New Feature: Export seed words in SeedQR format (on screen QR).
- New Feature: Provide user with info about transaction level timelocks 
  ([nLockTime](https://en.bitcoin.it/wiki/NLockTime),
  [nSequence](https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki))
  when signing.
- Enhancement: New submenu for saved BIP-39 Passphrases allowing delete of saved entries.
- Enhancement: Add current temporary seed to Seed Vault from within Seed Vault menu.
  If current seed is temporary and not saved yet, `Add current tmp` menu item is 
  shown in Seed Vault menu.
- Enhancement: Speed up opening `Passphrase` menu when MicroSD card is available, by
  deferring card read (and decryption) until after `Restore Saved` menu item is selected.
- Enhancement: `12 Words` menu option preferred on the top of the menu in all the seed menus
  (rather than 24 words).
- Enhancement: Allow passphrase via USB if passphrase already set - operates on master seed.
- Enhancement: Improve BIP39 Passphrase UX when temporary seed is active and applicable.
- Enhancement: Continuation of removal of obsolete Mk2/Mk3 code-paths from master branch.
- Bugfix: Confusing first-time UX replaced with simple welcome screen.
- Bugfix: One instant retry on SE1 communication failures
- Bugfix: Handle any failures in slot reading when loading settings
- Bugfix: Add missing "First Time UX" for extended key import as master seed
- Bugfix: Hide `Upgrade Firmware` menu item if temporary seed is active (it cannot work)
- Bugfix: Disallow using master seed as temporary seed
- Bugfix: Do not allow `APPLY` of empty BIP-39 passphrase. Use "Restore Master" instead.
- Bugfix: Fix yikes in `Clone Coldcard` (thanks to AnchorWatch)

## 5.2.0 - 2023-10-10

- New Feature: Seed Vault. Store multiple temporary secrets into encrypted settings for simple
  recall and later use (AES-256-CTR encrypted by key based on the seed).
  Enable this functionality in `Advanced/Tools -> Danger Zone -> Seed Vault -> Enable`. 
  Use stored seeds from Seed Vault with top-level `Seed Vault` menu choice (once enabled).
  Can capture and hold master secret from any temporary (ephemeral) seed source,
  including: TRNG, Dice Rolls, SeedXOR, TAPSIGNER backups, Duress Wallets, BIP-85 derived
  values, BIP-39 passphrase wallets.
- New Feature: PSBTv2 support added! Enables new PSBT workflows and applications.
- New Feature: `Lock Down Seed` now works with every temporary secret (not just BIP39 passphrase)
- New Feature: BIP-39 Passphrase can now be added to any words-based temporary seed.
- New Feature: Add ability to back-up BIP39 Passphrase wallet (with passphrase encoded).
- New Feature: Return to main secret from temporary without need to reboot the device.
- Enhancement: Shortcut to `Batch Sign PSBT` via `Ready To Sign` -> `Press (9)`
- Enhancement: Waste less storage space by removing old plausible deniability code
  which was only needed for Mk1 - Mk3 where SPI flash was an external chip.
- Enhancement: Remove obsolete Mk2/Mk3 code-paths from master branch.
- Enhancement: BIP39 Passphrase is now internally handled as an temporary secret.
  Ability to see BIP-39 Passphrase after wallet is active via `View Seed Words`
  was removed as a consequence of this change. Benefit: passphrase no longer held
  in memory while in operation.
- Enhancement: Showing secrets now also displays extended private key (XPRV) for BIP-39
  passphrase wallets.
- Enhancement: Increase number of slots in settings memory from 64 to 100.
- Bugfix: Fixed off by one bug in `Trick Pins -> Login Countdown` menu.
- Nomenclature: "Ephemeral Seed" will now be called "Temporary Seed".

## 5.1.4 - 2023-09-08

- Bugfix: Most users would see a red light after upgrade to 5.1.3 from 5.1.2. Fixed.

## 5.1.3 - 2023-09-07

- New Feature: Batch sign multiple PSBT files. `Advanced/Tools -> File Management -> Batch Sign PSBT`
- Enhancement: `Sparrow Wallet` added as an individual export option (same file contents)
- Enhancement: change key origin information export format in multisig `addresses.csv` to match
  [BIP-0380](https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki#key-expressions)
  was `(m=0F056943)/m/48'/1'/0'/2'/0/0` now `[0F056943/48'/1'/0'/2'/0/0]`
- Enhancement: Address explorer UX cosmetics, now with arrows and dots.
- Enhancement: Linked settings (multisig, trick pins, backup password, hsm users and utxo cache)
  separation for new main secret.
- Rename `Unchained Capital` to `Unchained`
- Bugfix: Correct `scriptPubkey` parsing for segwit v1-v16
- Bugfix: Do not infer segwit just by availability of `PSBT_IN_WITNESS_UTXO` in PSBT.
- Bugfix: Remove label from Bitcoin Core `importdescriptors` export as it is no longer supported
  with ranged descriptors in version `24.1` of Core.
- Bugfix: Empty number during BIP-39 passphrase entry could cause crash.
- Bugfix: Signing with BIP39 Passphrase showed master fingerprint as integer. Fixed to show hex.
- Bugfix: Fixed inability to generate paper wallet without secrets
- Bugfix: Activating trick pin duress wallet copied multisig settings from main wallet
- Bugfix: SD2FA setting is cleared when seed is wiped after failed login due to policy SD2FA enforce.
  Prevents infinite seed wipe loop when restoring backup after 2FA MicroSD lost or damaged.
  SD2FA is not backed up and also not restored from older backups. If SD2FA is set up,
  it will not survive restore of backup.
- Bugfix: Terms only presented if main PIN was not chosen already.
- Bugfix: Preserve defined order of Login Countdown settings list.
- Bugfix: Remove unsupported trick pin option `Look Blank` from `if wrong` (not supported by bootrom).


## 5.1.2 - 2023-04-07

- Enhancement: Support all `SIGHASH` types (previously only `SIGHASH_ALL` was supported).
  This can enable specialized Bitcoin transactions involving multiple signers and even
  limited changes to the transaction after signing. To enable the most dangerous SIGHASH
  modes, you must change `Advanced -> Danger Zone -> Sighash Checks`. Warnings are shown
  for all of the new SIGHASH modes regardless of this setting.
- Enhancement: SeedXOR now supports 12 and 18 words mnemonics.
- Enhancement: Signing memory, speed optimizations.
- Enhancement: Docker repro build container improvements (non-privileged container)
- Bugfix: After extended private key and TAPSIGNER backup import into blank wallet,
  users needed to manually reboot Coldcard.
- Bugfix: Do not set SIGHASH type on foreign PSBT inputs
- Bugfix: "Validating..." screen would be shown twice in some cases. Improves signing performance.


## 5.1.1 - 2023-02-27

- Bugfix: Same as 5.1.0 but corrects issue which prevented 5.1.0 from being upgraded
  over SD card. No functional changes.


## 5.1.0 - 2023-02-27

- New Feature: "MicroSD card as Second Factor". Specially marked MicroSD card must be
  already inserted when (true) PIN is entered, or else seed is wiped. Add, remove and check
  cards in menu: `Settings -> Login Settings -> MicroSD 2FA`
- New Feature: Import TAPSIGNER encrypted backup as main or ephemeral seed, for PSBT signing.
- New Feature: Detached Bitcoin signature files (most exports)
    - Files exported are now signed with a detached signature. Look for a `.sig` file
      with the same name, and verify signature with your favourite Bitcoin tools.
      See "Signed Exports" in `docs/msg-signing.md` fo more information.
    - Coldcard can now verify signed files: 
        - SD card and Virtual disk `Advanced/Tools -> File Management -> Verify Sig File`
        - NFC `Advanced/Tools -> NFC Tools -> Verify Sig File`
- Address Explorer:
    - Enhancement: Application-specific derivation paths in `Address Explorer -> Applications`
    - Bugfix: Change value was ignored when generating addresses file
- Import Enhancements:
    - Add import multisig wallet via Virtual Disk
    - Add import extended private key via Virtual Disk and via NFC
    - Import seed in compact/truncated form (just 3-4 letters of each seed word)
    - Import extended private key as ephemeral seed
- Export Enhancements: 
    - Samourai POST-MIX and PRE-MIX descriptor export options added
    - Lily Wallet added
    - Ability to export all supported wallets via NFC (instead of SD card only)
    - Change electrum export file name from 'new-wallet.json' to 'new-electrum.json'
    - Allow export of Wasabi skeleton for Bitcoin Regtest.
- Backup Enhancement:
    - Option to save the backup file's encryption password for next backup. Then next
      backup is quick and simple: no need to record yet another 12 words.
- Enhancement: During seed generation from dice rolls, enforce at least 50 rolls
  for 12 word seeds, and 99 rolls for 24 word seeds. Statistical distribution check
- Enhancement: Single signature wallet generic descriptor export
  `Advanced -> Export Wallet -> Descriptor`. Both new format with internal/external
  in one descriptor `<0;1>` and standard with two descriptors are supported.
  added to prevent users from generating low-entropy seeds by rolling same value repeatedly.
- Bugfix: Offer import/export from/to Virtual Disk in UI even if SD Card is inserted.
- Bugfix: Recalculate extended key saved in settings upon chain change (BTC, XTN, XRT).
- Bugfix: Provide correct derivation path (m/84'/1'/0') for testnet Wasabi export.
- Bugfix: Properly display UX checkmark only if testnet (XTN, XRT) is enabled 
  in `Settings- > Danger Zone -> Testnet Mode`.
- Docs: Add `docs/rolls12.py` script for verifying dice rolls math for 12 word seeds.

## 5.0.7 - 2022-10-05

- NFC Enhancements: 
    - In older versions, multisig NFC import not offered if a MicroSD card was
      inserted, now this option provided Settings > Multisig Wallets > Import via NFC. NFC has
      to be enabled for this option to be visible in the menu.
    - NFC message signing (Advanced/Tools > NFC Tools > Sign Message). Send message
      in same format as Sign Text File over NFC, approve signing on Coldcard and send signed
      ASCII-armored message back over NFC.
    - Show address over NFC (Advanced/Tools > NFC Tools > Show Address).
    - Bugfix: Improved NFC commands exception handling 
    - Bugfix: Share single address over NFC from address explorer menu.
- HSM Enhancements: 
    - Dynamic HSM Whitelisting. Foreign outputs can be attested-to by signing them with
      private key corresponding to the address specified in HSM policy. Attestation
      signature MUST be provided in PSBT in a new proprietary field.
    - HSM policy hash is now displayed during first activation and in the HSM status
      response. This enables fast comparison against known policy hashes.
    - Thanks to [@straylight-orbit](https://github.com/straylight-orbit) for above items!
    - Now ignores HSM commands over USB, by default. To enable and use HSM features,
      go to Advanced/Tools > Enable HSM > Enable
- New Feature: Ephemeral Seeds: Advanced/Tools > Ephemeral Seed (more info in `docs/ephemeral.md`)
- Enhancement: New menu wraparound settings which allow you to scroll past top and bottom of 
  any menu (Settings > Menu Wrapping).
- Enhancement: Allow import of new descriptor type which specify both internal/external
  in single string (ie. `../<0;1>/..`). We still export in older format.
- Enhancement: add ability to specify address format in text file to be signed (3rd line of file)
- Bugfix: Correct parsing of unknown fields in PSBT: they are now passed through.
- Bugfix: Using lots of trick pins (7+), could lead to a case where the Coldcard would
  not accept the main pin, but trick pins continued to work. This release adds a
  workaround to avoid getting into that situation, and new units from the factory will
  ship with an updated bootrom (version 3.1.5).

## 5.0.6 - 2022-07-29

- Security release: Virtual Disk feature updated with bugfix to address potential security
  concerns and new security hardening changes. Upgrade strongly recommended.

## 5.0.5 - 2022-07-20

- Enhancement: BIP-85 derived passwords. Pick an index number, and COLDCARD will derive
  a deterministic, strong (136 bit) password for you. It will even type the password by
  emulating a USB keyboard. See new areas: Settings > Keyboard EMU and
  Settings > Derive Seed B85 > Passwords.
- Documentation: added `docs/bip85-passwords.md` documenting new BIP-85 passwords and
  keyboard emulation.
- Enhancement: BIP-85 derived values can now be exported via NFC, in addition to QR code.
- Enhancement: Allow signing transaction where foreign UTXO(s) are missing.
  Only applies to cases where partial signatures are being created.
  Thanks to [@straylight-orbit](https://github.com/straylight-orbit)
- Enhancement: QR Codes are now easier to scan in bright light. Thanks
  to [@russeree](https://github.com/russeree) for this useful fix!
- Bugfix: order of multisig wallet registration does NOT matter.
- Enhancement: Support import of multisig wallet from descriptor (only sortedmulti, BIP-67).
  Also support export of multsig wallet as descriptor.
- Enhancement: Address explorer can show "change" addresses for standard derivation paths
  for both single and multisig wallet.
- New tutorial: 2of2 multisig with 2x Coldcard signing device, and bitcoin-qt as
  coordinator, see `docs/bitcoin-core2of2desc.md`
- Enhancement: `OP_RETURN` is now a known script and is displayed in ascii when possible
- Bugfix: allow unknown scripts in HSM mode, with warning.

## 5.0.4 - 2022-05-27

- Enhancement: Optional USB protocol change which binds the ephemeral ECDH encryption 
  keys more tightly. Best used in HSM mode where a single long-term USB connection is
  expected. Thanks to [@DON-MAC-256](https://github.com/DON-MAC-256) for this feature.
- Enhancement: In HSM mode, when more than 1k approvals, handle overflow in display,
  thanks to [@straylight-orbit](https://github.com/straylight-orbit)
- Enhancement: Adds support for "Regtest" which are testnet coins on an isolated blockchain.
  It's only useful for developers, and should not be used otherwise.
- Enhancement: Major rework of test setup to use BitcoinCore on regtest, and support Linux devs.
- Enhancement: Pause waiting for incoming NFC data increased to 3 seconds, from one. Better 
  error reporting for debug purposes.
- Corrects obsolete domain name (`coldcardwallet.com`) in repro build script, thanks to
  [@xavierfiechter](https://github.com/xavierfiechter)
- Documentation: Secure element related fixes from [@lucasmoten](https://github.com/lucasmoten)
- Bugfix: Error if clone (receiving end) started without first inserting SD card, fixed.
- Bugfix: Reproducible build issues corrected, thanks to [@Ademan](https://github.com/Ademan)

## 5.0.3 - 2022-05-04

- Enhancement: Support P2TR outputs (pay to Taproot) in PSBT files. Allows
  on-screen verification of P2TR destination addresses (`bc1p..`) so you can send
  your BTC to them. Does **not** support signing, so you cannot operate a Taproot
  wallet with COLDCARD as the signing device... yet.

## 5.0.2 - 2022-04-19

- Adds NFC support for exporting to all the various wallet-types.
- Multisig wallet specs can be exported via NFC, and new multisig wallet can be imported over NFC.
- Menu re-org: 
    - "Export Wallet" now directly under Advanced Menu and
      duplicate link remains under File Management.
    - "Dump Summary" moved from Backup menu to Export
    - "Advanced" now "Advanced/Tools"
    - shuffled contents of Advanced menu
    - "New Wallet" renamed "New Seed Words"
- Text changes to match reality that writing "files" can happen to SD card or VirtDisk or NFC.
- New users will see some prompts to help them get started, after seed is set.
- 12 word seeds are now an option from the start, either by TRNG or Dice Roll
- Dice rolls (for new seed) moved from Import (a misnomer) to "New Seed Words"
- Duress wallet (from trick pin) will be 12-words if your true seed is 12-words
- Bugfix: allow sending to scripts that we cannot parse, with a warning, to support
  `OP_RETURN` and other outputs we don't understand well (yet).
- Bugfix: sending NFC things into the Coldcard was not working, fixed.


## 5.0.1 - 2022-03-24

- bugfix: red light whenever MCU keys changed or seed installed first time.

## 5.0.0 - 2022-03-14

Mk4 - New hardware

- (Mk3&Mk4) Performance improved: some internal objects cached to reduce delays when
  accessing master secret. Helps address explorer, many USB commands and signing.
- Enhancement: Power-down during the login countdown now resets the time delay to force 
  attacker (or yourself) to start over with full delay time.
- Enhancement: if an XFP of zero is seen in a PSBT file, assume that should be replaced by
  our current XFP value and try to sign the input (same for change outputs and change-fraud
  checks). This makes building a workable PSBT file easier and could be used to preserve
  privacy of XFP value itself. A warning is shown when this happens.
- Enhancement: "Advanced > Export XPUB" provides direct way to show XPUB (or ZPUB/YPUB) for
  BIP-84 / BIP-44 / BIP-49 standard derivations, as a QR. Also can show XFP and master XPUB.
- (Mk4) PSBT files up to 2 megabytes now supported
