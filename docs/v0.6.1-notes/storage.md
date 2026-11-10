# v0.6.1: storage, disk encryption and key fixes (internal security review of v0.6.0)

- **Fixed (low): a power cut during the first format could leave the data partition refused at every boot**
  (R060-S1, ADR-370). The format's 4 KiB superblock write torn after 1 to 7 sectors made the partition neither
  blank nor valid (`BadChecksum`). That exact state is now an interrupted format and is formatted again; any other
  damaged superblock is still refused. Tests: `crates/store/tests/wrapped.rs::a_torn_superblock_write_during_the_format_is_formatted_again`,
  `a_damaged_superblock_of_a_used_disk_is_still_refused`.
- **Fixed (low): `urmqtt-disk` wrote plaintext copies of an encrypted disk readable by every local user**
  (R060-S2, ADR-371): the conversion journal of `encrypt`, and the files of `export-db` and `backup-extract`, are
  now mode 0600 (also over an existing file) and synced. Tests: `tools/disk/tests/convert.rs::the_conversion_journal_file_is_owner_only`,
  `tools/disk/tests/keys.rs::plaintext_copies_of_an_encrypted_disk_are_owner_only`.
- **Documented (low): a passphrase change does not lock out a leaked passphrase** (R060-S3, ADR-372): the disk key
  stays the same, so an earlier copy of the header still opens with the old passphrase. The console's log line and
  the tool now say so, and the documents say that a leak needs `urmqtt-disk rekey`, then `keys add`.
- **Documented (low): encryption with the key in the image does not protect a snapshot of a single-disk VPS**
  (R060-S7, ADR-373): the installer writes the key to the ESP of the same disk. SECURITY.md and DEPLOY.md no longer
  promise it; use `disk_key_source = "console"` against snapshots.
- **Warned (low): weak disk passphrases and low PBKDF2 costs** (R060-S4, ADR-374): `urmqtt-disk keys` warns about
  a new slot below the default 300 000 iterations or under a passphrase shorter than 20 characters; KNOWN-ISSUES
  lists the limit. Test: `tools/disk/tests/keys.rs::a_weak_new_slot_is_warned_about`.
