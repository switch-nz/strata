# Strata

An offline forensic image examiner. Cross-platform, no dependencies beyond
the Python standard library, and nothing it does touches the network.

Evidence is opened read-only, and every action an examiner takes is written to
a tamper-evident audit log.

![The Strata interface in both themes: evidence tree, directory listing, hex view with the core sample, and the inspector](docs/screenshot.png)

*Both themes in one frame — dark above the diagonal, light below. The evidence
is a synthetic volume: every byte of it was generated for this screenshot.*

---

## Evidence it opens

**Image formats**

| Format | Notes |
|---|---|
| EWF | `.E01` and `.L01`, including split segment sets |
| Raw / dd | single-file images and split sets (`.001`, `.002`, …) |
| VMDK | flat, sparse, and stream-optimized |
| VHDX | fixed and dynamic; a differencing disk is detected and reported, not merged |
| VHD | fixed, dynamic and differencing; a differencing disk is read through its parent, which must be the exact disk it was made from |
| VDI | VirtualBox dynamic and fixed disks; a differencing or undo disk is refused, since it holds only a change from another disk |
| DMG | Apple UDIF images with raw, zero-fill, zlib, bzip2, LZMA and LZFSE chunks; an encrypted or segmented image, or one with ADC chunks, is refused |
| QCOW2 | versions 2 and 3, including compressed clusters; an encrypted disk, or one with a backing file, external data file, subcluster tables or non-zlib compression, is refused |
| RAID 0 / 1 / 5 | assembled from member images (raw, E01 and the other image formats): the examiner gives the level, chunk size, RAID 5 layout, member order and data offsets; RAID 5 can be read with one member missing, and mirrors and parity are compared and reported as observed |
| AD1 | AccessData logical images |
| AFF4 | a Map over one or more ImageStreams, or a bare ImageStream, zlib/Deflate-compressed or stored; a striped or segmented multi-volume set, or any other compression method, is refused |

**Logical evidence** — a folder, a zip, or a single file opened as an exhibit
in its own right.

**Volume layout** — MBR, including logical partitions in extended
partitions, and GPT, including damaged tables, protective-MBR
cases, and discrepancies between the partition table and the boot record.
Unpartitioned gaps are shown rather than hidden.

**Acquisition integrity** — stored acquisition hashes are recovered and can be
re-verified; EWF chunk checksums are checked as data is read, and a chunk that
fails is reported rather than silently returned.

## Filesystems

Every one of these is parsed directly. Deleted entries, file slack and
unallocated space are reachable throughout.

| Filesystem | What is read |
|---|---|
| **NTFS** | MFT records and attributes, resident and non-resident; data runs; LZNT1-compressed, sparse and encrypted attributes; valid data length (bytes past it read as zeros, as Windows returns them); alternate data streams; `$STANDARD_INFORMATION` and `$FILE_NAME` timestamps separately; the directory index; deleted records |
| **FAT12/16/32** | boot parameter block, cluster chains, long filenames (checked against their short name's checksum), deleted entries with the first character recovered from a surviving long name, file slack, allocated-extent map |
| **exFAT** | allocation bitmap, up-case table, cluster chains including contiguous (NoFatChain) streams, deleted entries, slack |
| **ext2/3/4** | inodes, extent trees and legacy block maps, inline data, symlinks, and **jbd2 journal recovery** — superseded metadata recovered from the journal is reported as such |
| **APFS** | container superblock, object map, B-tree walking, volume records, file extents, the allocation map, and transparently compressed files (zlib, LZVN) |
| **HFS+/HFSX** | catalog and extents-overflow B-trees, both forks, file hard links, listed directory hard links, and transparently compressed files (zlib, LZVN) |

**Encrypted volumes** — BitLocker (FVE), LUKS1 and LUKS2 (Argon2id/i/d and
PBKDF2 keyslots) unlock with a password or recovery key. The key is held for
the session only, and is never written into the case.

## The core sample

The strip beside the hex view is a map of whatever is currently in scope.
Anything up to 64 MB is read end to end and every byte of it classified;
above that, each band of the strip is classified from sixteen reads spread
evenly across it, so a region is judged on more than its first few bytes.
How much was read is shown beneath the strip.
It doubles as the scrollbar: all of what you are looking at is on screen at
once, and the current position is always in context.

It follows the selection. With an exhibit selected it maps the whole image;
select a partition and it redraws over that volume alone; select a file — or
one of its named streams — and it maps that file end to end, at full
resolution for anything small enough. So the same strip answers "where is the
encrypted region on this disk" and "where does the payload start inside this
file", depending on what is selected.

Each region is classified as one of:

| Class | Meaning |
|---|---|
| **zeroed** | all zero, or more than 90% zero |
| **0xFF fill** | all `0xFF` — unwritten flash, or a wiped region |
| **text** | over 85% printable with entropy below 6.0 |
| **structured** | low entropy with binary structure — records, tables, headers |
| **dense** | entropy above 6.0 — compressed, or already-encoded media |
| **high entropy** | entropy above 7.6 — reads as encrypted or compressed |

Partitions, search hits and marks are drawn onto the same strip, so an
encrypted container, a wiped span, or a run of carved hits is visible as a
shape before anything has been opened. Entropy is reported in bits per byte
alongside the classification, and the measurement window is always stated.

## Analysis

**Artefacts** — seventeen parsers: volume layout, encrypted volumes, the change
journal (`$UsnJrnl`), the NTFS log (`$LogFile`, shown as recorded), prefetch, shortcuts and Jump Lists, Recycle Bin,
well-known registry keys, shellbags, Amcache and ShimCache, browser history,
Windows event logs, file-type verification, timeline, hashing every file,
signature carving, and the content index. Each says what it will cost before
it runs, and a triage set covers the quick ones in a single pass.

Also read: SQLite databases including recovery of deleted records, ESE/EDB
databases, LevelDB stores, PST and mbox mail, Office documents (OOXML and
OpenDocument), PDF, photograph EXIF and GPS, and cryptocurrency wallet
material — BIP-39 seed phrases and Base58Check/Bech32 addresses, each
checksum-verified, with near-misses reported separately.

**Registry** — hives parsed directly, with transaction log replay so that
pending changes are applied and reported, and recovery of deleted keys and
values from free cells.

**Timeline** — every timestamp on a volume, or across tagged items from every
exhibit, on one activity graph with range selection and filtering. NTFS
timestamp-consistency observations are raised where `$STANDARD_INFORMATION`
and `$FILE_NAME` disagree.

**Search** — literal and regex, ASCII and UTF-16LE, across file contents,
filenames, or raw media including unallocated space. Coverage is reported:
what was searched, what was skipped as encrypted or compressed, and where the
walk was truncated.

**Carving** — 29 built-in signatures across images, documents, archives,
databases, email, media, system artefacts and executables. Where a format
carries its own length, that length is used instead of scanning for a footer;
every hit records how its length was decided. Custom header/footer signatures
can be added.

**Hashing** — MD5, SHA-1 and SHA-256, with hash-set import and matching
against known-bad, known-good and notable sets.

**ATT&CK** — technique tagging that keeps the examiner's own attributions
separate from the tool's suggestions, and never promotes one to the other.

## Interface

- Canvas hex view with the core sample, a data interpreter showing both byte
  orders, on-disk structure templates, and a split view for comparing two
  offsets
- Directory listing with file-type verification, hashes and timestamps as
  columns; a gallery view for images
- Preview pane that renders images, text and documents, and **never executes
  HTML, SVG or scripts** — active content is removed before rendering and what
  was removed is listed
- Marks, tags and categories; saved searches; a command palette; keyboard
  shortcuts; six themes including two high-contrast
- Offsets can be shown from the start of the image, the volume, or the file

## Cases

- A case is a folder: the record itself, plus a rebuildable cache beside it
- Several exhibits per case, and several examiners working at once
- Extraction of files and folders with per-item hashes and a manifest; an
  extracted file can be added back as its own exhibit
- Self-contained HTML report
- Append-only, hash-chained audit log that reports where it was altered,
  including entries cut from the end. The chain is not keyed: it shows
  tampering by anyone who does not also recompute every later hash, but
  cannot rule that out

## Not implemented

EWF v2 (Ex01), FileVault, reconstructing events from `$LogFile`, and carving
across fragments.

---

## Running it

Python 3.8 or later. No install step.

```bash
python3 run.py                                  # then open http://127.0.0.1:8722
python3 run.py image.E01 --examiner "A. Examiner"
python3 run.py --browser                        # open a browser once it is up
python3 run.py --port 9000 --host 0.0.0.0       # serve the interface to another machine
```

| Option | Default | |
|---|---|---|
| `image` | none | evidence to open at start |
| `--examiner` | `$STRATA_EXAMINER` | name recorded against every action |
| `--port` | `8722` | |
| `--host` | `127.0.0.1` | serving to other machines is **unauthenticated** — anyone who can reach the port can drive the session; use only on a trusted network |
| `--browser` | off | open a browser at the interface |
| `--read-only` | off | refuse export and report writing for this run; examination still works |

Preferences are kept per examiner beside the application, never in a case.
Set `STRATA_CONFIG_DIR` to put them somewhere else.

An optional native module speeds up encrypted-volume unlocking and reading,
validating a dirty registry hive's transaction log, and the fuzzy hash
computed when bulk-hashing files. It ships as a separate per-release
download (`strata-native-<version>.zip`); extract it into the Strata folder
and it is picked up automatically. No examiner needs a Rust toolchain to
use it — only to build it from source, which is optional and only for
maintainers. Without it, Strata runs exactly as above, just slower for
those things; nothing else changes.

---

## Status and validation

This is an initial release. It does what is described here, but it is early,
and it will be refined — expect rough edges, and expect some of it to change.

Results are not guaranteed. Testing is ongoing rather than finished, and none
of it has been independently validated. Corroborate anything that matters
against another tool before you rely on it.

## Contributing

PRs are welcome — read [`CONTRIBUTING.md`](CONTRIBUTING.md) first for the
rules the project is reviewed against, and what a PR needs to include.

## Security

Vulnerabilities are handled privately — see
[`SECURITY.md`](SECURITY.md) for how to report one. Please do not open
public issues for anything exploitable.

## Licence

MIT — see [`LICENSE`](LICENSE). The name "Strata" is not licensed with the
source.
