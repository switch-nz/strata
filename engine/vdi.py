import array
import io
import os
import struct
import sys
import threading

from .text import t as _t

# VirtualBox's own disk format. A 64-byte text banner, then a pre-header
# (signature, version), a header, a block map of 32-bit entries and the
# blocks themselves. All fields are little-endian.
BANNER = b"<<< "
SIGNATURE = 0xBEDA107F
_SIG_AT = 0x40

TYPE_DYNAMIC = 1
TYPE_FIXED = 2
TYPE_UNDO = 3
TYPE_DIFF = 4

_TYPE_NAMES = {TYPE_DYNAMIC: "dynamic", TYPE_FIXED: "fixed",
               TYPE_UNDO: "undo", TYPE_DIFF: "differencing"}

# Block map entries that do not point at a block.
FREE = 0xFFFFFFFF          # never written: reads as zeros
ZERO = 0xFFFFFFFE          # written as all zeros and discarded: same

# A header is at least this long for version 1.1 (bytes from the header
# size field, offset 0x48, to the end of the parent UUID).
_HEADER_MIN = 0x190

_TABLE_CODE = next(c for c in "IL" if array.array(c).itemsize == 4)


class VdiError(Exception):

    def __init__(self, message, advice=""):
        Exception.__init__(self, message)
        self.message = message
        self.advice = advice


def looks_like_vdi(head):
    """Whether the first bytes carry a VirtualBox banner and signature.
    Both are checked: the banner is only text, and the signature alone is
    four bytes."""
    if len(head) < _SIG_AT + 4 or not head.startswith(BANNER):
        return False
    return struct.unpack_from("<I", head, _SIG_AT)[0] == SIGNATURE \
        and b"VirtualBox" in head[:_SIG_AT]


def _uuid(b):
    # VirtualBox writes its UUIDs in RTUUID order: the first three fields
    # little-endian.
    return "%08x-%04x-%04x-%s-%s" % (
        struct.unpack_from("<I", b, 0)[0], struct.unpack_from("<H", b, 4)[0],
        struct.unpack_from("<H", b, 6)[0], b[8:10].hex(), b[10:16].hex())


def parse_header(raw):
    """The fields Strata uses from a VDI's first 512 bytes, or VdiError."""
    if not looks_like_vdi(raw):
        raise VdiError(_t("vdi.not_a_vdi"))
    version, = struct.unpack_from("<I", raw, 0x44)
    major, minor = version >> 16, version & 0xFFFF
    if major != 1 or minor < 1:
        raise VdiError(_t("vdi.version_unsupported") % (major, minor),
                       "Only version 1.1 disks are read. Convert the disk "
                       "with VBoxManage clonehd, or open a newer export.")
    header_size, = struct.unpack_from("<I", raw, 0x48)
    if header_size < _HEADER_MIN or 0x48 + header_size > len(raw):
        raise VdiError(_t("vdi.header_size_invalid") % header_size)
    kind, flags = struct.unpack_from("<II", raw, 0x4C)
    off_blocks, off_data = struct.unpack_from("<II", raw, 0x154)
    sector_size, = struct.unpack_from("<I", raw, 0x168)
    disk_size, = struct.unpack_from("<Q", raw, 0x170)
    block_size, block_extra, blocks, allocated = struct.unpack_from(
        "<IIII", raw, 0x178)
    return {
        "type": kind, "flags": flags,
        "comment": raw[0x54:0x154].split(b"\x00")[0].decode("utf-8", "replace"),
        "off_blocks": off_blocks, "off_data": off_data,
        "sector_size": sector_size, "disk_size": disk_size,
        "block_size": block_size, "block_extra": block_extra,
        "blocks": blocks, "allocated": allocated,
        "uuid": _uuid(raw[0x188:0x198]),
        "parent_uuid": _uuid(raw[0x1B8:0x1C8]) if len(raw) >= 0x1C8 else None,
        "link_uuid": _uuid(raw[0x1A8:0x1B8]),
    }


class VdiImage:
    """A VirtualBox VDI disk. Blocks are found through a block map; blocks
    never written, or discarded, read as zeros. A differencing or undo disk
    holds only what changed from another disk and is refused rather than
    shown as though it were the whole disk. Only the disk is exposed: the
    banner, header and map are container metadata."""

    def __init__(self, path, fh):
        # The caller opens the file once, and this reader takes over the
        # handle (closing it in close()); `path` is only its name.
        self.path = path
        self.segment_paths = [path]
        self.findings = []
        self._pos = 0
        self._io_lock = threading.Lock()
        self._fh = fh
        try:
            self._open()
        except BaseException:
            self.close()
            raise

    def _open(self):
        file_size = os.fstat(self._fh.fileno()).st_size
        self._file_size = file_size
        info = parse_header(self._file_read(0, 512))
        self.info_fields = info
        self.image_type = info["type"]
        if self.image_type in (TYPE_DIFF, TYPE_UNDO):
            raise VdiError(
                _t("vdi.differencing_refused")
                % _TYPE_NAMES[self.image_type],
                "A disk of this kind holds only what changed from another "
                "disk, and reading it alone would show a mixture of zeros "
                "and changes. Convert the chain to one disk with VBoxManage "
                "clonehd and open that.")
        if self.image_type not in (TYPE_DYNAMIC, TYPE_FIXED):
            raise VdiError(_t("vdi.type_unrecognised") % self.image_type)
        bs = info["block_size"]
        if bs < 512 or bs & (bs - 1) or bs > (1 << 28):
            raise VdiError(_t("vdi.block_size_invalid") % bs)
        if info["block_extra"]:
            raise VdiError(_t("vdi.block_extra_unsupported")
                           % info["block_extra"])
        self._sector = info["sector_size"] if info["sector_size"] in (
            512, 1024, 2048, 4096) else 512
        if info["sector_size"] != self._sector:
            self.findings.append(
                "The header gives a sector size of %d bytes, which is not "
                "one Strata recognises; 512 is used." % info["sector_size"])
        self.size = info["disk_size"]
        # A map longer than the disk needs is never addressed, so a header
        # claiming more cannot make the map bigger than the disk.
        needed = -(-self.size // bs)
        n = min(info["blocks"], needed)
        if info["blocks"] < needed:
            self.findings.append(
                "The block map holds %d blocks, covering %d bytes of the "
                "%d-byte disk the header declares; the rest reads as zeros."
                % (info["blocks"], info["blocks"] * bs, self.size))
        if info["off_blocks"] + 4 * n > file_size:
            raise VdiError(_t("vdi.map_unreadable"))
        raw = self._file_read(info["off_blocks"], 4 * n)
        if len(raw) < 4 * n:
            raise VdiError(_t("vdi.map_unreadable"))
        table = array.array(_TABLE_CODE)
        table.frombytes(raw)
        if sys.byteorder == "big":
            table.byteswap()
        self._map = table
        self._block = bs
        self._data = info["off_data"]
        self._bad_blocks = set()
        seen = set()
        dupes = 0
        for e in table:
            if e in (FREE, ZERO):
                continue
            if e in seen:
                dupes += 1
            seen.add(e)
        if dupes:
            self.findings.append(
                "%d block map entries point at a block another entry "
                "already uses; both read the same data." % dupes)
        counted = len(seen)
        if counted != info["allocated"]:
            self.findings.append(
                "The header says %d blocks are allocated, but the block map "
                "points at %d; the map is what is read."
                % (info["allocated"], counted))
        self.bytes_per_sector = self._sector

    def _file_read(self, offset, length):
        if offset < 0 or length <= 0 or offset >= self._file_size:
            return b""
        length = min(length, self._file_size - offset)
        with self._io_lock:
            self._fh.seek(offset)
            return self._fh.read(length)

    def _block_read(self, blk, within, n):
        entry = self._map[blk] if blk < len(self._map) else FREE
        if entry in (FREE, ZERO):
            return bytes(n)
        base = self._data + entry * self._block
        if base + self._block > self._file_size \
                and blk not in self._bad_blocks:
            self._bad_blocks.add(blk)
            self.findings.append(
                "Block %d is recorded at file offset %d and runs past the "
                "end of the file; what is missing reads as zeros."
                % (blk, base))
        data = self._file_read(base + within, n)
        return data + bytes(n - len(data))

    def read_at(self, offset, length):
        if offset < 0 or offset >= self.size or length <= 0:
            return b""
        length = min(length, self.size - offset)
        out = bytearray()
        while length > 0:
            blk, within = divmod(offset, self._block)
            n = min(length, self._block - within)
            out += self._block_read(blk, within, n)
            offset += n
            length -= n
        return bytes(out)

    def read(self, n=-1):
        d = self.read_at(self._pos, self.size - self._pos if n < 0 else n)
        self._pos += len(d)
        return d

    def seek(self, off, whence=io.SEEK_SET):
        if whence == io.SEEK_SET:
            self._pos = off
        elif whence == io.SEEK_CUR:
            self._pos += off
        else:
            self._pos = self.size + off
        return self._pos

    def close(self):
        fh = getattr(self, "_fh", None)
        if fh is not None:
            fh.close()

    def verify(self, progress=None):
        import hashlib
        md5, sha1 = hashlib.md5(), hashlib.sha1()
        pos = 0
        while pos < self.size:
            d = self.read_at(pos, 1 << 20)
            if not d:
                break
            md5.update(d)
            sha1.update(d)
            pos += len(d)
            if progress:
                progress(pos / self.size)
        return {"computed_md5": md5.hexdigest(),
                "computed_sha1": sha1.hexdigest(),
                "stored_md5": None, "stored_sha1": None,
                "md5_match": None, "sha1_match": None,
                "note": _t("vdi.vdi_stores_acquisition_hash")}

    def info(self):
        f = self.info_fields
        acquisition = {
            "container size on disk": self._file_size,
            "unique id": f["uuid"],
            "block size": self._block,
            "blocks in map": len(self._map),
            "blocks allocated": sum(
                1 for e in self._map if e not in (FREE, ZERO)),
            "blocks discarded as zero": sum(
                1 for e in self._map if e == ZERO),
        }
        if f["comment"]:
            acquisition["comment"] = f["comment"]
        return {
            "format": "VirtualBox disk (VDI, %s)"
                      % _TYPE_NAMES.get(self.image_type, "unknown"),
            "segments": [os.path.basename(self.path)],
            "size": self.size,
            "bytes_per_sector": self.bytes_per_sector,
            "chunk_size": self._block,
            "acquisition": acquisition,
            "findings": list(self.findings),
        }
