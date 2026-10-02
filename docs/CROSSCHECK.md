# Cross-checking Strata against other readers

`tests/crosscheck.py` reads the same image with Strata and with independent
readers and reports every place they disagree. It exists because passing
Strata's own tests shows that Strata reads what Strata's authors expected, not
that it reads what other tools read. A disagreement is a lead, not a verdict:
either reader may be the one that is wrong.

## What is compared

Layer by layer, each side given the same input:

| Layer | Strata | Reference |
|---|---|---|
| Disk container (EWF, VHD, QCOW2, VMDK, VDI, DMG) | the engine's reader | libewf, libvhdi, libqcow, libvmdk, qemu-img |
| Partition table (GPT) | `volume.scan` | libvsgpt |
| Filesystem tree (NTFS, FAT, ext, HFS+) | the walker search and hashing share | libfsntfs, libfsfat, libfsext, libfshfs |

Containers are compared by size and by a digest of each 1 MiB chunk (all of
them, or with `--chunks N` the first and last few and a seeded random sample,
so a run can be repeated). Filesystems are compared by path, kind, size, a
digest of the first `--hash-bytes` of content, and extra streams (NTFS
alternate data streams, the HFS+ resource fork). Filesystem readers are given
Strata's own view of the partition, so a container difference cannot show up
as a filesystem one.

The references are optional. Each is used only if its Python package (or
program) is installed, and is reported as `missing` otherwise; `--list` says
what is installed and how to get the rest. Strata itself needs only the
standard library.

## Running it

    python3 tests/crosscheck.py                    synthetic corpus
    python3 tests/crosscheck.py --list             readers and cases
    python3 tests/crosscheck.py --case 'hfsplus*'  some cases
    python3 tests/crosscheck.py --images A.E01 ... real images
    python3 tests/crosscheck.py --strict           also fail on stale baseline entries

The exit status is 1 when a difference is not in the baseline. CI runs it on
every change to the engine (`.github/workflows/crosscheck.yml`).

## The baseline

`tests/crosscheck_baseline.json` lists the differences that are understood,
each with a case, a facet (`container`, `volumes`, `fs`), a kind (`only_strata`,
`only_ref`, `differs`, `error`), a key pattern and the reason it is accepted.
An entry without a reason is refused. Many entries are about the synthetic
images rather than the readers: a reference reader that refuses a fixture
(because the builder leaves out something real writers always write) is
recorded as an `error`, so the gap stays on the list instead of being quietly
skipped.

Add an entry only after finding out why the two disagree. If Strata is wrong,
fix Strata and leave the baseline alone.

## Real images

`--images` runs the same comparison over images you supply. File and folder
names are evidence, so for these they are replaced in everything printed and
saved by short stable tokens (`--names` turns that off); nothing about a real
image is written to the baseline, which refuses entries for anything but
synthetic cases; and results are saved to `crosscheck-out/`, which git
ignores. Review what you share from a real image before sharing it.

## Not yet covered

Encryption (BitLocker, LUKS), artefact parsers (event logs, registry, mail,
shortcuts, prefetch), AFF4, APFS and exFAT have no reference wired in, and
the ext4 fixture is not yet compared (see its baseline entry).
