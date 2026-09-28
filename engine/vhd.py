import io
import os
import struct
import threading

from .text import t as _t

# The "Conectix" hard disk footer format used by Virtual PC, Virtual
# Server and Hyper-V (VHD, not VHDX). The footer is always the last 512
# bytes of the file; a dynamic or differencing disk also carries an
# identical copy at the very start, but the copy at the end is the one
# the format itself treats as authoritative, so that is the one read
# here regardless of disk type.
SIGNATURE = b"conectix"
FOOTER_SIZE = 512

DISK_TYPE_FIXED = 2
DISK_TYPE_DYNAMIC = 3
DISK_TYPE_DIFFERENCING = 4

_DISK_TYPE_NAMES = {
    0: "none",
    1: "reserved",
    2: "fixed",
    3: "dynamic",
    4: "differencing",
    5: "reserved",
    6: "reserved",
}

class VhdError(Exception):

    def __init__(self, message, advice=""):
        Exception.__init__(self, message)
        self.message = message
        self.advice = advice

def looks_like_vhd(path):
    """Whether the last 512 bytes of `path` carry a VHD footer cookie.
    A fixed VHD's footer only exists at the end of the file, so unlike
    every other container here this has to look at the tail, not the
    head."""
    try:
        size = os.path.getsize(path)
        if size < FOOTER_SIZE:
            return False
        with open(path, "rb") as fh:
            fh.seek(size - FOOTER_SIZE)
            return fh.read(8) == SIGNATURE
    except OSError:
        return False

def _checksum(footer):
    # One's complement of the sum of every footer byte, with the stored
    # checksum field itself (bytes 64-67) treated as zero.
    total = sum(footer[:64]) + sum(footer[68:FOOTER_SIZE])
    return (~total) & 0xFFFFFFFF

def parse_footer(footer):
    """Parse and validate a 512-byte VHD footer, returning its fields.
    Raises VhdError if the cookie is missing or the checksum does not
    match -- it does not judge the disk type, so a caller can still see
    what a footer with a bad checksum claims to be."""
    if len(footer) < FOOTER_SIZE:
        raise VhdError(_t("vhd.footer_short"))
    if footer[:8] != SIGNATURE:
        raise VhdError(_t("vhd.footer_missing_cookie"))
    disk_type, = struct.unpack_from(">I", footer, 60)
    current_size, = struct.unpack_from(">Q", footer, 48)
    original_size, = struct.unpack_from(">Q", footer, 40)
    stored_checksum, = struct.unpack_from(">I", footer, 64)
    data_offset, = struct.unpack_from(">Q", footer, 16)
    return {
        "disk_type": disk_type,
        "current_size": current_size,
        "original_size": original_size,
        "data_offset": data_offset,
        "unique_id": _guid(footer[68:84]),
        "checksum_ok": stored_checksum == _checksum(footer),
    }

def _guid(b):
    return "%s-%s-%s-%s-%s" % (b[0:4].hex(), b[4:6].hex(), b[6:8].hex(),
                               b[8:10].hex(), b[10:16].hex())

# Dynamic disk header ("cxsparse"), 1024 bytes, at the footer's data offset.
SPARSE_COOKIE = b"cxsparse"
HEADER_SIZE = 1024
UNUSED = 0xFFFFFFFF
MAX_CHAIN = 16

def parse_sparse_header(hdr):
    if len(hdr) < HEADER_SIZE or hdr[:8] != SPARSE_COOKIE:
        raise VhdError(_t("vhd.dynamic_header_missing"))
    stored, = struct.unpack_from(">I", hdr, 36)
    total = sum(hdr[:36]) + sum(hdr[40:HEADER_SIZE])
    if stored != (~total) & 0xFFFFFFFF:
        raise VhdError(_t("vhd.dynamic_header_checksum"))
    table_offset, = struct.unpack_from(">Q", hdr, 16)
    max_entries, block_size = struct.unpack_from(">II", hdr, 28)
    locators = []
    for i in range(8):
        at = 576 + 24 * i
        code = hdr[at:at + 4]
        _space, length = struct.unpack_from(">II", hdr, at + 4)
        offset, = struct.unpack_from(">Q", hdr, at + 16)
        if code != b"\x00\x00\x00\x00" and length:
            locators.append((code, length, offset))
    return {
        "table_offset": table_offset,
        "max_entries": max_entries,
        "block_size": block_size,
        "parent_id": _guid(hdr[40:56]),
        "parent_name": hdr[64:576].decode("utf-16-be", "replace")
                       .split("\x00")[0],
        "locators": locators,
    }

class VhdImage:
    """A VHD disk. A fixed VHD is raw disk data followed by a 512-byte
    Conectix footer. A dynamic VHD stores the disk in blocks found through
    a block allocation table; blocks never written read as zeros. A
    differencing VHD is a dynamic one whose unwritten sectors come from
    its parent disk. Only the disk is exposed -- the footer, header and
    tables are container metadata, not part of what the guest OS saw."""

    def __init__(self, path, _chain=None):
        self.path = path
        self.segment_paths = [path]
        self.findings = []
        self._pos = 0
        self._io_lock = threading.Lock()
        self.parent = None
        self.parent_how = None
        self._chain = (_chain or ()) + (os.path.realpath(path),)

        file_size = self._file_size = os.path.getsize(path)
        if file_size < FOOTER_SIZE:
            raise VhdError(_t("vhd.footer_short"))

        self._fh = open(path, "rb")
        try:
            self._fh.seek(file_size - FOOTER_SIZE)
            footer = self._fh.read(FOOTER_SIZE)
            info = parse_footer(footer)
            self.disk_type = info["disk_type"]
            self.unique_id = info["unique_id"]

            if info["disk_type"] not in (DISK_TYPE_FIXED, DISK_TYPE_DYNAMIC,
                                         DISK_TYPE_DIFFERENCING):
                raise VhdError(
                    _t("vhd.disk_type_unrecognised")
                    % _DISK_TYPE_NAMES.get(info["disk_type"],
                                           "0x%08X" % info["disk_type"]))

            if not info["checksum_ok"]:
                raise VhdError(_t("vhd.footer_checksum_mismatch"))

            if info["disk_type"] == DISK_TYPE_FIXED:
                data_size = file_size - FOOTER_SIZE
                self.size = min(info["current_size"], data_size)
                if info["current_size"] != data_size:
                    self.findings.append(
                        "The footer's current size (%d bytes) does not match "
                        "the data before the footer (%d bytes); the smaller "
                        "of the two is exposed."
                        % (info["current_size"], data_size))
            else:
                self._open_sparse(info, footer, file_size)
        except Exception:
            self.close()
            raise

        self.bytes_per_sector = 512
        self.original_size = info["original_size"]

    # -- dynamic and differencing disks ------------------------------------

    def _open_sparse(self, info, footer, file_size):
        self._file_size = file_size
        if self._file_read(0, FOOTER_SIZE) != footer:
            self.findings.append(
                "The copy of the footer at the start of the file differs "
                "from the one at the end. The one at the end is the one the "
                "format treats as authoritative, and is the one used.")
        hdr = parse_sparse_header(self._file_read(info["data_offset"],
                                                  HEADER_SIZE))
        bs = hdr["block_size"]
        if bs < 512 or bs % 512 or bs > (1 << 28):
            raise VhdError(_t("vhd.block_size_invalid") % bs)
        n = hdr["max_entries"]
        raw = (self._file_read(hdr["table_offset"], 4 * n)
               if 4 * n <= file_size else b"")
        if len(raw) < 4 * n:
            raise VhdError(_t("vhd.bat_unreadable"))
        self._bat = struct.unpack(">%dI" % n, raw)
        self._block = bs
        self._bitmap_size = ((bs // 512 + 7) // 8 + 511) // 512 * 512
        self._bitmaps = {}
        self._bad_blocks = set()
        self.size = info["current_size"]
        if n * bs < self.size:
            self.findings.append(
                "The block allocation table covers %d bytes, less than the "
                "%d-byte disk the footer declares; the rest reads as zeros."
                % (n * bs, self.size))
        if info["disk_type"] == DISK_TYPE_DIFFERENCING:
            self._open_parent(hdr)

    def _parent_candidates(self, hdr):
        here = os.path.dirname(os.path.abspath(self.path))
        seen = []
        for code, length, offset in hdr["locators"]:
            data = self._file_read(offset, min(length, 4096))
            if code in (b"W2ru", b"W2ku"):
                text = data.decode("utf-16-le", "replace")
            elif code in (b"Wi2r", b"Wi2k"):
                text = data.decode("latin-1")
            elif code == b"MacX":
                text = data.decode("utf-8", "replace")
                if text.startswith("file://"):
                    text = text[7:]
            else:
                continue
            text = text.split("\x00")[0].strip()
            if not text:
                continue
            local = text.replace("\\", os.sep)
            if code in (b"W2ru", b"Wi2r"):
                seen.append(("relative locator",
                             os.path.normpath(os.path.join(here, local))))
            else:
                seen.append(("absolute locator", local))
            # A disk and its parent are usually copied into one folder, so
            # whatever path the locator gives, try its name beside the child.
            base = local.replace("/", os.sep).split(os.sep)[-1]
            seen.append(("locator's file name, beside this file",
                         os.path.join(here, base)))
        if hdr["parent_name"]:
            seen.append(("parent name in the header, beside this file",
                         os.path.join(here, hdr["parent_name"])))
        return seen

    def _open_parent(self, hdr):
        if len(self._chain) >= MAX_CHAIN:
            raise VhdError(_t("vhd.parent_chain_too_long") % MAX_CHAIN)
        tried = []
        for how, candidate in self._parent_candidates(hdr):
            # Only a regular file: a locator is written by whoever made the
            # image, and must not lead to a device or a pipe.
            if candidate in tried or not os.path.isfile(candidate):
                tried.append(candidate)
                continue
            if os.path.realpath(candidate) in self._chain:
                raise VhdError(_t("vhd.parent_loop") % candidate)
            parent = VhdImage(candidate, self._chain)
            if parent.unique_id != hdr["parent_id"]:
                parent.close()
                raise VhdError(
                    _t("vhd.parent_mismatch") % (
                        os.path.basename(candidate), parent.unique_id,
                        hdr["parent_id"]),
                    "A differencing disk is only meaningful over the exact "
                    "parent it was made from; reading it over another would "
                    "mix two disks' contents.")
            self.parent, self.parent_how = parent, how
            self.segment_paths = [self.path] + parent.segment_paths
            if parent.size != self.size:
                self.findings.append(
                    "The parent disk is %d bytes and this one %d; sectors "
                    "the parent does not hold read as zeros."
                    % (parent.size, self.size))
            return
        raise VhdError(
            _t("vhd.parent_not_found") % (hdr["parent_name"] or "unnamed"),
            "Put the parent disk in the same folder as this file, under the "
            "name it was created with, and open this file again.")

    def _file_read(self, offset, length):
        # Offsets come from the image's own headers and tables: one past the
        # end of the file reads as nothing rather than failing the seek.
        if offset < 0 or length <= 0 or offset >= self._file_size:
            return b""
        with self._io_lock:
            self._fh.seek(offset)
            return self._fh.read(length)

    def _below(self, offset, length):
        """Bytes this disk does not hold: the parent's, or zeros."""
        if self.parent is None:
            return bytes(length)
        got = self.parent.read_at(offset, length)
        return got + bytes(length - len(got))

    def _bitmap(self, blk, entry):
        got = self._bitmaps.get(blk)
        if got is None:
            got = self._file_read(entry * 512, self._bitmap_size)
            got += bytes(self._bitmap_size - len(got))
            if len(self._bitmaps) > 256:
                self._bitmaps.clear()
            self._bitmaps[blk] = got
        return got

    def _block_read(self, blk, within, n):
        disk_off = blk * self._block + within
        entry = self._bat[blk] if blk < len(self._bat) else UNUSED
        if entry == UNUSED:
            return self._below(disk_off, n)
        base = entry * 512 + self._bitmap_size
        if base + self._block > self._file_size and blk not in self._bad_blocks:
            self._bad_blocks.add(blk)
            self.findings.append(
                "Block %d is recorded at file offset %d, past the end of "
                "the file; what is missing reads as zeros."
                % (blk, entry * 512))
        if self.parent is None:
            data = self._file_read(base + within, n)
            return data + bytes(n - len(data))
        # Differencing: each sector comes from this file if its bit is set
        # in the block's bitmap (most significant bit first), else from the
        # parent.
        bitmap = self._bitmap(blk, entry)
        out = bytearray()
        pos = within
        end = within + n
        while pos < end:
            sector = pos // 512
            mine = bitmap[sector >> 3] & (0x80 >> (sector & 7))
            stop = pos
            while stop < end:
                s = stop // 512
                if bool(bitmap[s >> 3] & (0x80 >> (s & 7))) != bool(mine):
                    break
                stop = (s + 1) * 512
            stop = min(stop, end)
            if mine:
                data = self._file_read(base + pos, stop - pos)
                out += data + bytes(stop - pos - len(data))
            else:
                out += self._below(blk * self._block + pos, stop - pos)
            pos = stop
        return bytes(out)

    def read_at(self, offset, length):
        if offset < 0 or offset >= self.size or length <= 0:
            return b""
        length = min(length, self.size - offset)
        if self.disk_type == DISK_TYPE_FIXED:
            data = self._file_read(offset, length)
            if len(data) < length:
                data = data + bytes(length - len(data))
            return data
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
        if self.parent is not None:
            self.parent.close()

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
        return {"computed_md5": md5.hexdigest(), "computed_sha1": sha1.hexdigest(),
                "stored_md5": None, "stored_sha1": None,
                "md5_match": None, "sha1_match": None,
                "note": _t("vhd.vhd_stores_acquisition_hash")}

    def info(self):
        kind = _DISK_TYPE_NAMES.get(self.disk_type, "fixed")
        acquisition = {
            "original size": self.original_size,
            "container size on disk": os.path.getsize(self.path),
            "unique id": self.unique_id,
        }
        if self.disk_type != DISK_TYPE_FIXED:
            acquisition["block size"] = self._block
            acquisition["blocks allocated"] = sum(
                1 for e in self._bat if e != UNUSED)
            acquisition["blocks in table"] = len(self._bat)
        if self.parent is not None:
            acquisition["parent"] = self.parent.path
            acquisition["parent found by"] = self.parent_how
            acquisition["parent type"] = _DISK_TYPE_NAMES.get(
                self.parent.disk_type)
        findings = list(self.findings)
        if self.parent is not None:
            findings += ["Parent %s: %s" % (os.path.basename(self.parent.path),
                                            f)
                         for f in self.parent.info()["findings"]]
        return {
            "format": "Virtual PC / Hyper-V disk (VHD, %s)" % kind,
            "segments": [os.path.basename(p) for p in self.segment_paths],
            "size": self.size,
            "bytes_per_sector": self.bytes_per_sector,
            "chunk_size": (1 << 20) if self.disk_type == DISK_TYPE_FIXED
                          else self._block,
            "acquisition": acquisition,
            "findings": findings,
        }
