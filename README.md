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
| Raw / dd | including split raw sets |
| VMDK | flat, sparse, and stream-optimized |
| VHDX | fixed and dynamic; a differencing disk is detected and reported, not merged |
| AD1 | AccessData logical images |

**Logical evidence** — a folder, a zip, or a single file opened as an exhibit
in its own right.

**Volume layout** — MBR and GPT, including damaged tables, protective-MBR
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
| **NTFS** | MFT records and attributes, resident and non-resident; data runs; LZNT1-compressed, sparse and encrypted attributes; alternate data streams; `$STANDARD_INFORMATION` and `$FILE_NAME` timestamps separately; the directory index; deleted records |
| **FAT12/16/32** | boot parameter block, cluster chains, long filenames, deleted entries with the first character recovered, file slack, allocated-extent map |
| **exFAT** | allocation bitmap, up-case table, cluster chains including contiguous (NoFatChain) streams, deleted entries, slack |
| **ext2/3/4** | inodes, extent trees and legacy block maps, inline data, symlinks, and **jbd2 journal recovery** — superseded metadata recovered from the journal is reported as such |
| **APFS** | container superblock, object map, B-tree walking, volume records, file extents, and the allocation map |
| **HFS+/HFSX** | catalog and extents-overflow B-trees, and both forks |

**Encrypted volumes** — BitLocker (FVE) and LUKS1 unlock with a password or
recovery key. The key is held for the session only, and is never written into
the case.

## The core sample

The strip beside the hex view is a map of whatever is currently in scope,
drawn by classifying every region of it rather than by sampling a few bytes.
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

**Artefacts** — sixteen parsers: volume layout, encrypted volumes, the change
journal (`$UsnJrnl`), prefetch, shortcuts and Jump Lists, Recycle Bin,
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
  shortcuts; light and dark themes
- Offsets can be shown from the start of the image, the volume, or the file

## Cases

- A case is a folder: the record itself, plus a rebuildable cache beside it
- Several exhibits per case, and several examiners working at once
- Extraction of files and folders with per-item hashes and a manifest; an
  extracted file can be added back as its own exhibit
- Self-contained HTML report
- Append-only, hash-chained audit log that reports where it was altered

## Not implemented

EWF v2 (Ex01), FileVault, BitLocker with the Elephant diffuser, LUKS2 with
Argon2, ANSI PST, `$LogFile`, and carving across fragments. Shadow copies are
listed but cannot yet be opened.

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

Preferences are kept per examiner beside the application, never in a case.
Set `STRATA_CONFIG_DIR` to put them somewhere else.

---

## Status and validation

This is an initial release. It does what is described here, but it is early,
and it will be refined — expect rough edges, and expect some of it to change.

Results are not guaranteed. Testing is ongoing rather than finished, and none
of it has been independently validated. Corroborate anything that matters
against another tool before you rely on it.

## Security

Vulnerabilities are handled privately — see
[`SECURITY.md`](SECURITY.md) for how to report one. Please do not open
public issues for anything exploitable.

## Licence

MIT — see [`LICENSE`](LICENSE). The name "Strata" is not licensed with the
source.
