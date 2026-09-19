# Roadmap

What Strata does not do yet, kept as a working list of features and known
work. What it already does is in the [README](../README.md), and what changed
in each release is in the [CHANGELOG](../CHANGELOG.md).

This is a plan, not a promise. An item is ticked only once it has been
exercised against real evidence, not just a synthetic image.

Legend — `[ ]` not started · `[~]` partly there

---

## Correctness

A forensic tool's worst failure is a confident wrong answer, so this comes
before anything new.

- [x] Previewing a genuine case can still upgrade its schema or create its
      `cache/` folder. It writes only to Strata's own record, never to
      evidence, but a preview should not write at all.

---

## Evidence formats

Roughly in order of how often an examiner meets them. Everything below is
recognised and refused by name today; these entries are about *reading* it.

- [ ] **Ex01 / Lx01** (EWF v2) — detected and refused. Same lineage as the
      E01 already read, with a different header and compression framing.
      Cheapest real win of the set.
- [~] **Split raw sets** (`.001`, `.002`, …) — joined into one exhibit, with
      a finding for a missing or wrongly sized piece. Tested only on
      synthetic sets so far; check against sets written by FTK Imager, `dd`
      with `split`, and Guymager.
- [ ] **VHD** (the older `conectix` format, not VHDX) — a fixed VHD is raw
      with a footer appended and nearly free; dynamic and differencing disks
      need their own block allocation table.
- [ ] **QCOW2**, **VDI**, **DMG**, **AFF / AFF4** — AFF4 is ZIP-based and is
      deliberately not matched by signature, since refusing every ordinary
      archive to catch one image format would be wrong far more often than
      right.
- [ ] **RAID** reassembly (0 / 1 / 5) from member images.

### Shadow copies

- [ ] **Read a Volume Shadow Copy.** Snapshots are found and listed today, but
      none can be opened. Reading one means a block-redirect overlay over the
      volume, then browsing its tree as a filesystem in its own right, plus
      the differential-area store types.

### Filesystems

- [ ] **HFS** (the original, not HFS+), `com.apple.decmpfs` compressed files,
      and hard links through the private metadata directory.
- [ ] **APFS snapshots** — the superblock's snapshot metadata is located but
      snapshots are not listed or read.

### Encryption

- [ ] **BitLocker startup keys (`.BEK`) and clear-key volumes.** Both protector
      types are recognised, but unlocking only accepts a password or a
      recovery key, so neither can be used yet.
- [ ] **BitLocker with the Elephant diffuser** — Vista and Windows 7 volumes
      are identified and refused rather than decrypted wrongly.
- [ ] **LUKS2 with Argon2 against real cryptsetup images** — implemented and
      verified against synthetic images built to cryptsetup's layout; real
      cryptsetup-written volumes still need to be confirmed before this can
      be called done.
- [ ] **FileVault 2** (APFS and Core Storage).

---

## Artefacts

- [ ] **`$LogFile`** — the log NTFS keeps for crash recovery. A different
      structure from `$UsnJrnl` and a much shorter window, but it records the
      operations rather than a summary per file.
- [ ] **Browser disk cache** — the on-disk cache format, separate from the
      history databases already read.
- [ ] **Event ID descriptions**, and timelining across logs.
- [ ] **PST:** ANSI (32-bit) files are refused today; OST-specific
      structures are not handled.
- [ ] **Legacy Office body text** — Word's piece table, Excel's BIFF stream,
      PowerPoint's records. Properties are read; the body is deliberately left
      unread rather than guessed at.

---

## Memory

A memory image is not a disk. It has no partition table, no filesystem and no
directory, so almost nothing above the container layer applies: the volume
tree, the file listing, signature carving and the timeline all assume
structures that are not there. What it has instead is the operating system's
live data structures, scattered across physical pages in an order the image
does not record.

That makes this a second product sharing a shell, not a feature. It is listed
in full so its size is on the page, and so a partial implementation is never
mistaken for the thing itself.

**Why it is worth doing anyway.** Everything that never touches the disk lives
only here: the key for the volume that will not open, a chat window, a process
running from a file deleted before imaging, the command line of something that
ran once. On a full-disk-encrypted machine seized running, memory is most of
the evidence.

In the order each step depends on the last:

- [ ] **Containers.** Raw first; then Microsoft crash dumps (`PAGEDU64` /
      `PAGEDUMP`, which carry the physical run list in their header and are
      easier than raw), LiME, and AFF4-imager output. Hibernation files are
      Xpress-compressed — a decompression problem before a memory one, and the
      same family as the LZXPRESS already written for prefetch.
- [ ] **Physical to virtual** — find and walk the page tables per
      architecture: x64 four-level paging, PAE, and ARM64.
- [ ] **Identify the operating system from the image itself**, not from what
      the examiner was told. A near-miss profile yields process lists that look
      plausible and are wrong in detail; refuse an image whose kernel cannot be
      identified rather than analyse it against a neighbour.
- [ ] **Structure definitions without a dependency** — ship a compact table
      generated from public symbol data, or derive offsets from the image by
      pattern. The whole feature turns on this choice; make it deliberately.
- [ ] **Processes** — the active list and a pool-scan cross-check, reported
      separately, since a process hidden from one but present in the other is
      a finding. Command lines, environment, handles, modules, and parent/child
      with the caveat that PIDs are reused.
- [ ] **Injected and unbacked code** — executable regions with no file behind
      them, and permissions that disagree with the on-disk image. Reported as
      observed, not as a verdict.
- [ ] **Network** — sockets and connections, live and residual.
- [ ] **Registry in memory** — mapped hives, which can differ from disk.
- [ ] **Keys and secrets** — BitLocker FVEK and LUKS master keys, under the
      same rule as today: session-lifetime only, never written to the case.
- [ ] **Files cached in memory**, and the page file examined together with the
      image it came from.
- [ ] **Presentation** — processes as roots, modules, handles and regions
      beneath; the hex view and core sample over physical offsets.

**Before any of it ships:** a memory image from a machine whose state is known
independently, so a process list is checked against what was actually running.
Agreeing with another tool is agreement, not verification.

---

## Analysis

- [ ] Image similarity (perceptual hashing) -- needs pixel-level image
      decoding this codebase does not otherwise have a reason to carry, so
      it is scoped separately from fuzzy hashing (done).
- [ ] Carving across fragments, starting with bi-fragment gap carving.
- [ ] A map view for GPS coordinates.

---

## Interface

- [ ] Configurable columns in the folder view, and the filter controls search
      already has (both can share `filesearch.matches_filters`).
- [ ] Read-only mode that refuses export and report writing.
- [ ] Ask before re-running an artefact replaces its earlier result — fine on a
      first pass, wrong once someone has worked from the earlier output.
- [ ] Template editor, so an examiner can define a structure without Python.
      The templates in `engine/structure.py` are already declarative enough to
      make this mostly an interface problem.
- [ ] Diff two images, or two snapshots of one volume.
- [ ] Scripting or plugin API for custom parsers.
- [ ] Multi-examiner case notes with attribution.
- [~] Localisation — the interface and engine messages already load from
      `web/strings/`; only English (en-GB) exists.

---

## Performance and debt

- [ ] Tagged items are keyed on the filesystem handle (MFT record / inode):
      stable within an image, but a tag will not follow the same volume
      re-acquired into another image.

---

## Open questions

- **Independent validation.** None of the parsers has been validated against
  reference tooling on shared evidence; a repeatable comparison against an
  established tool is the candidate before any new filesystem.
- **Fuzz corpus growth.** The saved corpus is small; a standing fuzz job with
  coverage feedback would find the next #15 before a user does.

