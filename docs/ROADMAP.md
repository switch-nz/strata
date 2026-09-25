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
- [~] **Split raw sets** (`.001`, `.0000`, `.aa`, …) — the set shapes real
      acquisition tools write are joined into one exhibit: FTK Imager's
      three-digit `.001`, Guymager's zero-based numbering at whatever width
      the disk needs, and `dd` with `split`, both its default alphabetic
      suffixes and `-d` numeric ones. A missing, wrongly sized or mixed-width
      piece raises a finding naming the piece in the set's own numbering.
      Verified against genuine `split` and `dd` output; FTK Imager and
      Guymager naming was reconstructed from their documentation and source,
      so sets written by those tools themselves still need checking.
- [ ] **VHD** (the older `conectix` format, not VHDX) — a fixed VHD is raw
      with a footer appended and nearly free; dynamic and differencing disks
      need their own block allocation table.
- [ ] **QCOW2**, **VDI**, **DMG**, **AFF / AFF4** — AFF4 is ZIP-based and is
      deliberately not matched by signature, since refusing every ordinary
      archive to catch one image format would be wrong far more often than
      right.
- [ ] **RAID** reassembly (0 / 1 / 5) from member images.

### Shadow copies

- [~] **Read a Volume Shadow Copy.** Snapshots are found and listed, and a
      snapshot can now be opened: a block-redirect overlay over the volume plus
      the differential-area store types let Strata browse a snapshot's tree as a
      filesystem in its own right. Tested on synthetic images only so far.

### Filesystems

- [ ] **HFS** (the original, not HFS+), `com.apple.decmpfs` compressed files,
      and hard links through the private metadata directory.
- [~] **APFS snapshots** — snapshots are listed and can be opened as a
      read-only view of the volume. Tested on synthetic images only so far.

### Encryption

- [ ] **BitLocker startup keys (`.BEK`) and clear-key volumes** — implemented
      and verified against synthetic FVE volumes built to the published
      format spec (including cross-checking the protector-type values
      against an independent tool); a real `.BEK` file and a real
      clear-key volume from actual Windows-run BitLocker still need to be
      confirmed before this can be called done.
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
- [x] **Browser disk cache** — Chromium blockfile (what Chrome and Edge on
      Windows write for web content), Chromium Simple Cache and Firefox cache2
      entries are read (URL, status, content type, times), separate from the
      history databases. Blockfile entries come from the cache files rather
      than the index, so dropped entries are found and marked. Bodies are not
      read. Checked against real Chrome and Edge caches (blockfile) and Chrome's
      service worker script cache; Firefox cache2 is synthetic only so far.
- [ ] **Event ID descriptions**, and timelining across logs.
- [ ] **PST:** ANSI (32-bit) files are refused today; OST-specific
      structures are not handled.
- [~] **Legacy Office body text** — Word's piece table, Excel's BIFF stream
      and PowerPoint's records are decoded, and whatever cannot be proven from
      the file is a finding rather than a guess. Checked against nearly 400
      files written by real Office; Excel formula, boolean and error cells
      are not read yet, and Word 6/95 files are refused.

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
- [ ] Carving across fragments beyond the first slice: a gap that is not a
      currently-allocated extent (both fragments sit in unallocated space,
      with unrelated deleted data between them), sizer-only (no-footer)
      signatures, and three or more fragments. The first slice --
      footer-terminated types split around exactly one allocated gap -- is
      done.
- [ ] A map view for GPS coordinates.

---

## Interface

- [ ] Configurable columns in the folder view, and the filter controls search
      already has (both can share `filesearch.matches_filters`).
- [x] Read-only mode that refuses export and report writing.
- [ ] Template editor, so an examiner can define a structure without Python.
      The templates in `engine/structure.py` are already declarative enough to
      make this mostly an interface problem.
- [x] Diff two images, or two snapshots of one volume.
- [ ] Scripting or plugin API for custom parsers.
- [ ] Multi-examiner case notes with attribution.
- [~] Localisation — the interface and engine messages already load from
      `web/strings/`; only English (en-GB) exists.

---

## Performance and debt

- [x] Tagged items are keyed on the filesystem handle (MFT record / inode),
      which is stable only within an image; tags now follow the same volume
      re-acquired into another image, matched on the filesystem's own
      identifier.

---

## Open questions

- **Independent validation.** None of the parsers has been validated against
  reference tooling on shared evidence; a repeatable comparison against an
  established tool is the candidate before any new filesystem.
- **Fuzz corpus growth.** The saved corpus is small; a standing fuzz job with
  coverage feedback would find the next #15 before a user does.

