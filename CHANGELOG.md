# Changelog

Notable changes to Strata. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). While the version is 0.x, a minor
release may change behaviour.

Add a line under **Unreleased** in the same PR as the change. Examiners read
this list, so write for them: what changed in what Strata reads, reports or
records, not how the code changed.

## [Unreleased]

### Added

- **Tags follow a volume when it is re-acquired into another image.** Tags
  are keyed to the filesystem handle of the file they name, which is stable
  only within one image, so the same volume imaged again arrived with its
  tags left behind on the old exhibit. Each detected volume now records its
  filesystem's own identifier — an NTFS or exFAT serial, an ext4 or APFS
  UUID — and when a volume the case has seen before is acquired, its tags
  move to the new exhibit. A volume whose identifier matches several the
  case already holds is reported rather than guessed
  ([#82](https://github.com/switch-nz/strata/issues/82)).
- **Split raw sets** (`.001`, `.002`, …, or numbered from `.000`) are opened
  as one disk. Previously opening the first piece read that piece alone, with
  nothing to say the rest of the disk was missing. The set is joined whichever
  piece is opened. A missing piece is reported, and only the pieces before
  the gap are joined. A piece opened on its own because an earlier one is
  missing is reported as starting partway through the disk. A piece whose
  size differs from the others is reported, since data after it may be at the
  wrong offset ([#19](https://github.com/switch-nz/strata/issues/19)).

### Fixed
- **The mail viewer crashed on a PST message with a sender or recipient.**
  PST gives a single formatted address string per field where mbox gives a
  list, and the viewer assumed every message used mbox's shape, so any PST
  message with a `From` or `To` failed to render at all. Both shapes are
  now handled.
- **A message's body was never shown.** mbox and PST both decode a
  message's text server-side already, but the mail viewer only ever listed
  headers — clicking a message did nothing. A message can now be opened to
  read its plain-text body (or, for an HTML-only message, its visible text
  with the markup stripped out — never rendered as HTML) and its attachment
  names
  ([#93](https://github.com/switch-nz/strata/issues/93)).
- **A tagged, deleted, contiguous exFAT file could export the wrong content.**
  exFAT reads a NoFatChain stream by its extent, not by walking the FAT —
  the same fix #91 made for FAT and ext4's `deleted` flag, but keyed on a
  different field this format never carried through a tag. Tagged items now
  record whether an exFAT stream is contiguous, so re-exporting one by
  handle alone reads it the way it needs to be read
  ([#94](https://github.com/switch-nz/strata/issues/94)).
- A damaged AD1's chunk size, if implausible, is no longer trusted for how
  much to allocate when a chunk fails to decompress; a header cut short
  before its own declared fields end is now refused instead of raising an
  unhandled error. A rejected AD1 no longer leaves its files held open,
  which on Windows kept them locked.
- A contiguous exFAT stream no longer builds one list entry per cluster to
  find its extent. A corrupted stream length on a large genuine volume could
  ask for hundreds of millions of entries, which was slow enough to look like
  a hang; the extent is now computed directly, regardless of its length
  ([#43](https://github.com/switch-nz/strata/issues/43)).
- **Exporting a tagged deleted file could silently export the wrong content.**
  "Export tagged items" sends a filesystem handle rather than a full listing
  entry, and the flag saying an item is deleted did not make the trip. A
  deleted file was then read as if it were live: on FAT this returned only
  its first cluster for anything spanning more than one, and on ext4 an
  unlinked inode whose blocks were already cleared exported as empty instead
  of recovering from the journal. Deleted status, and the modified/accessed/
  created times already recorded for the tag, now travel with the export, so
  the manifest is complete and the content is read the way a deleted entry
  needs to be
  ([#85](https://github.com/switch-nz/strata/issues/85)).
- **Previewing a case no longer writes to it.** Opening a case to peek at
  it — the case picker in the Open dialog — upgraded old schemas, created a
  `cache/` folder with an empty content index in it, and could add audit
  entries to the case record before anything was opened. On a read-only
  archive folder this made preview fail outright with a permission error.
  A preview is now read-only end to end: it changes nothing in the case
  folder, and a case there that predates some tables or columns is served
  as-is and left for the next full open to upgrade.

- **Sparse ext4 files read back wrong.** Where a file had a hole — a range
  never written, which reads as zeros — the data after the hole was shifted
  back into it and the end of the file was missing, so both the content and
  its hash were wrong. Holes now read as zeros in place, including a hole at
  the end of a file
  ([#19](https://github.com/switch-nz/strata/issues/19)).
- **A truncated compressed chunk in an E01 was returned short, silently.**
  The part that did decompress was served as if it were the whole chunk, with
  no finding, and a read running across that chunk stopped there, so the rest
  of the image could not be read in that pass. Such a chunk is now reported,
  what decompressed is kept, and the missing remainder reads as zeros so
  everything after it stays at the right offset. A chunk whose compressed data
  is complete but missing its checksum is reported as unverified
  ([#19](https://github.com/switch-nz/strata/issues/19)).
- **Deleted FAT long filenames were assembled out of order.** A deleted file
  whose long name spans more than one directory entry was shown with the
  pieces in the wrong order — `Removed document.txt` appeared as
  `ent.txtRemoved docum`. The pieces are now joined in the order they belong
  ([#19](https://github.com/switch-nz/strata/issues/19)).
- **Slack for a deleted FAT file larger than one cluster was reported inside
  the file.** Deletion frees the file's cluster chain, and slack was worked
  out from that freed chain, so it pointed into the file's own content rather
  than past its end; the file's runs likewise showed only its first cluster.
  Both now follow the clusters the recovered content is read from. Where
  those clusters run off the end of the volume, or a live file's chain is
  broken short, no slack is reported, since where the file ends is unknown
  ([#19](https://github.com/switch-nz/strata/issues/19)).
- **Files in an exFAT directory spanning several clusters could be missing.**
  A directory whose clusters are stored contiguously, without a FAT chain,
  was listed from its first cluster only, so anything recorded in its later
  clusters was not shown, searched or put on the timeline. Such a directory
  is now read in full
  ([#19](https://github.com/switch-nz/strata/issues/19)).
- **ext4 inline files over 60 bytes, and inline directories, were misread.**
  With inline data, a small file or directory is kept inside its inode: the
  first 60 bytes in the block map and the rest in an extended attribute.
  Content past 60 bytes was taken from the wrong part of the inode, so the
  file read back wrong and hashed wrong, and an inline directory's entries
  were not listed. Both are now read from where ext4 stores them
  ([#19](https://github.com/switch-nz/strata/issues/19)).
- **A file beside an E01 could stop the image opening.** Any file with the
  same name and a three-letter extension, such as `case.txt` next to
  `case.E01`, was taken as one of the image's segments. A lettered name only
  counts as a segment now once the set reaches `.E99`, the point where EWF
  moves on to lettered names, and only if the file is an EWF segment
  ([#19](https://github.com/switch-nz/strata/issues/19)).
- A damaged ext4 extent tree whose index points back at itself, or at one
  node many times over, no longer hangs reading a file. Each node is read
  once, and a node at the wrong depth is ignored
  ([#19](https://github.com/switch-nz/strata/issues/19)).
- A registry hive cut short no longer raises an error. One ending inside its
  base block opens with a finding that it holds no keys. Recovering deleted
  keys and values from one cut short part-way through its data stops at the
  end of what is there
  ([#19](https://github.com/switch-nz/strata/issues/19)).
- **A truncated or damaged chunk in an AD1 file shifted every chunk after
  it.** AD1 stores a file's content in fixed-size compressed chunks, and a
  chunk that decompressed to less than its full size, or not at all, was
  appended as-is or served as its own raw compressed bytes, so every later
  chunk's data landed at the wrong offset, and hashing carried the same
  fault. Each chunk now keeps its own place: a chunk that could not be fully
  recovered is reported and the gap reads as zeros, without moving anything
  after it
  ([#19](https://github.com/switch-nz/strata/issues/19)).
- **A damaged or hostile VMDK could hang or exhaust memory opening it.** A
  handful of header and grain-table fields — the descriptor's location, the
  grain size, the number of entries per grain table, and a compressed
  grain's declared size — were trusted outright. An implausible value in any
  of them could seek or allocate by that value directly, which crashed the
  open, exhausted memory, or in one case made every read across the disk
  slow enough to stall an examination. Each is now checked against what the
  file could plausibly hold; an extent whose layout is genuinely implausible
  is refused, and a field that only overruns the file is clipped and
  reported. A grain whose compressed data ends early is now also reported,
  rather than silently read as if it were complete
  ([#19](https://github.com/switch-nz/strata/issues/19)).

### Changed

- **Times recorded with no time zone are no longer shown as UTC.** FAT
  timestamps, the DOS times inside shellbags, and exFAT timestamps whose
  entry records no valid UTC offset are local time on a clock whose zone the
  media does not say. They were marked and displayed as UTC, and converted to
  the chosen display zone as if they were. They are now shown exactly as
  recorded, with no zone, no conversion and no label, in the interface and
  the report. Deciding which zone they belong to is left to the examiner.
  The timeline still has to place them somewhere to sort them, and orders
  them as if they were UTC ([#19](https://github.com/switch-nz/strata/issues/19)).

## [0.1.2] - 2026-09-17

A correctness release: exFAT timestamps, and damaged ext, NTFS and exFAT
volumes that could stop an examination. Upgrade from 0.1.1.

### Fixed

- exFAT timestamps were shifted by the time zone of the device that wrote
  them. An exFAT entry records local time together with that device's UTC
  offset, and the offset was ignored, so local time was shown as UTC. Times
  are now converted to UTC using the recorded offset. An entry that records
  no valid offset is still shown unadjusted and labelled UTC: treat those
  times as the device's local time
  ([#19](https://github.com/switch-nz/strata/issues/19)).
- An ext2, ext3 or ext4 volume whose journal is missing or damaged no longer
  raises an error when a deleted file's details or content are read, or when a
  file's journal history is asked for. It reports that no history was
  recovered instead
  ([#15](https://github.com/switch-nz/strata/issues/15)).
- An NTFS volume whose `$MFT` cannot be read no longer claims millions of
  records it does not have, which made listing it hang; the record count is
  held to what the volume can contain, with a finding when it had to be cut.
  A damaged MFT record is also no longer returned as a real one the second
  time it is looked up, which could stop a file's details from showing
  ([#15](https://github.com/switch-nz/strata/issues/15)).
- An exFAT volume whose boot sector claims more clusters than the image
  holds is read using what the image actually holds, with a finding, so a
  damaged boot sector can no longer exhaust memory
  ([#15](https://github.com/switch-nz/strata/issues/15)).

### Known issues

The known issues listed for 0.1.0 still apply, with two changes: exFAT
timestamps are now converted wherever the entry records a valid offset, and
the crashes and hangs tracked in
[#15](https://github.com/switch-nz/strata/issues/15) are fixed. Two registry
crashes on truncated hives remain
([#19](https://github.com/switch-nz/strata/issues/19)).

## [0.1.1] - 2026-09-17

A security and evidence-integrity release. Upgrade from 0.1.0.

### Security

- **A flat VMDK could make Strata read a file that is not part of the
  exhibit.** A flat VMDK is a descriptor plus a file holding the disk data,
  and the descriptor names that file. The name was followed wherever it led:
  to another file on the examiner's machine, which was then shown, hashed,
  searched and reported as the disk, or to a network path, which on Windows
  can send the examiner's credentials to that host. The data file is now read
  only from beside the descriptor, and any other name is refused before
  anything is touched
  ([GHSA-5ww2-4xpg-4jpq](https://github.com/switch-nz/strata/security/advisories/GHSA-5ww2-4xpg-4jpq)).
  If you opened flat VMDKs from an untrusted source with 0.1.0, check that
  each one's data file sat beside its descriptor.

### Fixed

- **Previewing or opening a file that is not a case could change it.** An
  empty file or any SQLite database — a browser history file, for example —
  had case tables written into it on preview, and was turned into a folder on
  opening. A case is now only a folder holding `case.sqlite`, recognised
  without writing to anything, and anything else is refused and left untouched
  ([#23](https://github.com/switch-nz/strata/issues/23)).

### Known issues

The known issues listed for 0.1.0 still apply.

## [0.1.0] - 2026-09-17

The first release. Everything is described in the [README](README.md). In
brief:

### Evidence

- EWF (`.E01`, `.L01`) including split segment sets; single-file raw/dd;
  VMDK (flat, sparse and stream-optimized); VHDX (fixed and dynamic);
  AccessData AD1.
- Size and offset fields in EWF segment files are bounded, so a damaged
  image records a finding instead of exhausting memory
  ([#14](https://github.com/switch-nz/strata/pull/14)).
- Logical evidence: a folder, a zip or a single file opened as an exhibit.
- MBR and GPT volume layout, including damaged tables and the gaps between
  partitions.
- Stored acquisition hashes recovered and re-verifiable; EWF chunk
  checksums checked as data is read.
- BitLocker and LUKS1 unlock by password or recovery key, held for the
  session only.

### Filesystems

- NTFS, FAT12/16/32, exFAT, ext2/3/4 with jbd2 journal recovery, APFS and
  HFS+/HFSX, parsed directly, with deleted entries, file slack and
  unallocated space reachable throughout.
- A contiguous exFAT run that claims more than the cluster heap holds is cut
  off at its end, with a finding
  ([#17](https://github.com/switch-nz/strata/pull/17)).

### Analysis

- Sixteen artefact parsers with a triage set, including `$UsnJrnl`,
  prefetch, LNK and Jump Lists, Recycle Bin, registry keys, shellbags,
  Amcache and ShimCache, browser history, event logs and a timeline.
- Registry hives with transaction-log replay and deleted key recovery.
- SQLite (with deleted record recovery), ESE, LevelDB, PST, mbox, Office
  documents, PDF, EXIF and cryptocurrency wallet material.
- Literal and regex search with stated coverage; signature carving (29
  built-in signatures); MD5, SHA-1 and SHA-256 hashing with hash sets;
  ATT&CK tagging.

### Interface and cases

- Hex view with the core sample, data interpreter and structure templates;
  directory listing and gallery; a preview pane that never executes active
  content.
- Six themes, including midnight, sepia and two high-contrast themes, chosen
  from a theme picker dialog
  ([#1](https://github.com/switch-nz/strata/pull/1),
  [#9](https://github.com/switch-nz/strata/pull/9)).
- Cases as folders with several exhibits and examiners, file extraction
  with a hashed manifest, a self-contained HTML report and a hash-chained,
  append-only audit log.

### Project

- CI on Linux, Windows and macOS across Python 3.8 to 3.13, with unit tests
  and a smoke test of the running app; `SECURITY.md`, `CONTRIBUTING.md` and
  issue templates ([#12](https://github.com/switch-nz/strata/pull/12)).
- Parser tests built from synthetic images, mutation fuzzing of the parsers,
  tests of the request gate, and CodeQL
  ([#13](https://github.com/switch-nz/strata/pull/13)).

### Not implemented

EWF v2 (Ex01), split raw sets, FileVault, BitLocker with the Elephant
diffuser, LUKS2 with Argon2, ANSI PST, `$LogFile`, carving across fragments,
and opening shadow copies (they are listed only).

### Known issues

Corroborate results in these areas with another tool before relying on them.

- **Some parsers return wrong or missing results without a warning**
  ([#19](https://github.com/switch-nz/strata/issues/19)):
  - exFAT timestamps ignore the recorded UTC offset but are labelled UTC.
  - Files in the later clusters of a contiguous exFAT directory are not
    listed.
  - Sparse ext4 files read back with their data at the wrong offsets; ext4
    inline files over 60 bytes, and inline directories, are misread.
  - Deleted FAT long filenames made of several parts are assembled out of
    order, and slack for a deleted multi-cluster FAT file is reported in the
    wrong place.
  - A truncated compressed EWF chunk is returned short, without a finding.
  - Opening the first segment of a split raw set reads that segment alone,
    with nothing to say the rest of the disk is missing. Join the segments
    first.
- A file with a three-letter extension beside an EWF image, such as
  `case.txt` next to `case.E01`, is taken as a segment and stops the image
  opening ([#19](https://github.com/switch-nz/strata/issues/19)).
- Some damaged images crash or hang a parser instead of recording a finding
  ([#15](https://github.com/switch-nz/strata/issues/15),
  [#19](https://github.com/switch-nz/strata/issues/19)).

[Unreleased]: https://github.com/switch-nz/strata/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/switch-nz/strata/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/switch-nz/strata/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/switch-nz/strata/releases/tag/v0.1.0
