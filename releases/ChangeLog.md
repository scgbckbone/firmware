# Change Log

This lists the changes in the most recent firmware, for each hardware platform.

# Shared Improvements - Both Mk4 and Q

- Enhancement: Text word-wrap done more carefully so never cuts off any text, and yet
  doesn't waste space.
- Bugfix: `Add current tmp` option, which could be shown in `Seed Vault` menu under
  specific circumstances, would corrupt master settings if selected.
- Bugfix: PUSHDATA2 in bitcoin script caused yikes.
- Bugfix: Warning for unknown scripts was not shown at the top of the signing story.


# Mk4 Specific Changes

## 5.4.3 - 2025-05-14

- Bugfix: With both NFC & Virtual Disk OFF, user cannot exit `Export Wallet` menu. Gets stuck
  in export loop and needs reboot to escape.
- Bugfix: Part of extended keys in stories were not always visible.


# Q Specific Changes

## 1.3.3Q - 2025-05-14

- Bugfix: Do not allow to teleport PSBTs from SD card when CC has no secrets.
- Bugfix: Calculator login mode: added "rand()" command, removed support
  for variables/assignments.


# Release History

- [`History-Q.md`](History-Q.md)
- [`History-Mk4.md`](History-Mk4.md)
- [`History-Mk3.md`](History-Mk3.md)

