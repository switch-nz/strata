import array
import io
import os
import struct
import sys
import threading
import zlib

from .inflate import inflate_ended
from .text import t as _t

# QEMU's copy-on-write format, version 2 and 3. Everything is big-endian.
# A two-level table maps the virtual disk to clusters: the L1 table points
# at L2 tables, each of which points at data clusters.
MAGIC = b"QFI\xfb"

_OFFSET_MASK = 0x00FFFFFFFFFFFE00      # bits 9-55 of an L1 or L2 entry
_COMPRESSED = 1 << 62
_ZERO_FLAG = 1

# Incompatible feature bits (version 3).
_F_DIRTY = 1 << 0
_F_CORRUPT = 1 << 1
_F_EXTERNAL_DATA = 1 << 2
_F_COMPRESSION_TYPE = 1 << 3
_F_EXTENDED_L2 = 1 << 4

_L2_CACHE = 64
_CLUSTER_CACHE = 16
_MIN_BITS, _MAX_BITS = 9, 21


class QcowError(Exception):

    def __init__(self, message, advice=""):
        Exception.__init__(self, message)
        self.message = message
        self.advice = advice


def looks_like_qcow(head):
    return head[:4] == MAGIC


def parse_header(raw):
    """The fields Strata uses from a QCOW2 header, or QcowError."""
    if len(raw) < 72 or raw[:4] != MAGIC:
        raise QcowError(_t("qcow2.not_a_qcow"))
    version, = struct.unpack_from(">I", raw, 4)
    if version not in (2, 3):
        raise QcowError(
            _t("qcow2.version_unsupported") % version,
            "Only QCOW2 (version 2) and its version 3 revision are read. "
            "Convert the disk with qemu-img convert -O raw.")
    backing_off, backing_len, cluster_bits, size = struct.unpack_from(
        ">QIIQ", raw, 8)
    crypt, l1_size, l1_off, refcount_off, refcount_clusters, nb_snaps, \
        snaps_off = struct.unpack_from(">IIQQIIQ", raw, 32)
    out = {
        "version": version, "backing_off": backing_off,
        "backing_len": backing_len, "cluster_bits": cluster_bits,
        "size": size, "crypt": crypt, "l1_size": l1_size, "l1_off": l1_off,
        "snapshots": nb_snaps, "incompatible": 0, "compression": 0,
    }
    if version == 3:
        if len(raw) < 104:
            raise QcowError(_t("qcow2.header_short"))
        out["incompatible"], = struct.unpack_from(">Q", raw, 72)
        header_len, = struct.unpack_from(">I", raw, 100)
        if header_len >= 105 and len(raw) >= 105:
            out["compression"] = raw[104]
    return out


class Qcow2Image:
    """A QCOW2 disk. Clusters never allocated, or marked as zero, read as
    zeros; compressed clusters are inflated as they are read. A disk with a
    backing file holds only what changed from that file and is refused
    rather than shown as though it were the whole disk, as are disks that
    are encrypted, keep their data in an external file, or use compression
    or table layouts Strata cannot read. Only the disk is exposed: header,
    tables and reference counts are container metadata."""

    def __init__(self, path):
        self.path = path
        self.segment_paths = [path]
        self.findings = []
        self._pos = 0
        self._io_lock = threading.Lock()
        self._fh = open(path, "rb")
        try:
            self._open()
        except Exception:
            self.close()
            raise

    def _open(self):
        file_size = os.path.getsize(self.path)
        self._file_size = file_size
        info = parse_header(self._file_read(0, 112))
        self.header = info
        if info["backing_off"] and info["backing_len"]:
            name = self._file_read(info["backing_off"],
                                   min(info["backing_len"], 1023))
            name = name.decode("utf-8", "replace").replace("\\", "/") \
                .split("/")[-1] or "unnamed"
            raise QcowError(
                _t("qcow2.backing_refused") % name,
                "A disk with a backing file holds only what changed from "
                "that file, and reading it alone would show a mixture of "
                "zeros and changes. Flatten the chain with qemu-img "
                "convert -O raw and open the result.")
        if info["crypt"]:
            raise QcowError(
                _t("qcow2.encrypted") % info["crypt"],
                "The clusters are encrypted. Decrypt the disk with "
                "qemu-img convert first, or open the volume through its "
                "own encryption once it is a raw image.")
        inc = info["incompatible"]
        if inc & _F_EXTERNAL_DATA:
            raise QcowError(_t("qcow2.external_data"))
        if inc & _F_EXTENDED_L2:
            raise QcowError(_t("qcow2.extended_l2"))
        if inc & _F_COMPRESSION_TYPE and info["compression"] != 0:
            raise QcowError(
                _t("qcow2.compression_unsupported") % info["compression"],
                "Only zlib-compressed clusters are read. Convert the disk "
                "with qemu-img convert -O raw.")
        unknown = inc & ~(_F_DIRTY | _F_CORRUPT | _F_EXTERNAL_DATA
                          | _F_COMPRESSION_TYPE | _F_EXTENDED_L2)
        if unknown:
            raise QcowError(_t("qcow2.features_unknown") % unknown)
        if inc & _F_DIRTY:
            self.findings.append(
                "The image was not closed cleanly (its dirty flag is set), "
                "so its reference counts may be out of date. The data "
                "clusters are read as they are recorded.")
        if inc & _F_CORRUPT:
            self.findings.append(
                "QEMU marked this image corrupt. What is read is what the "
                "tables record, which may not be what the guest last wrote.")
        bits = info["cluster_bits"]
        if not _MIN_BITS <= bits <= _MAX_BITS:
            raise QcowError(_t("qcow2.cluster_bits_invalid") % bits)
        self._bits = bits
        self._cluster = 1 << bits
        self._l2_entries = self._cluster // 8
        self.size = info["size"]
        span = self._cluster * self._l2_entries
        needed = -(-self.size // span)
        n = min(info["l1_size"], needed)
        if info["l1_size"] < needed:
            self.findings.append(
                "The L1 table holds %d entries, covering %d bytes of the "
                "%d-byte disk the header declares; the rest reads as zeros."
                % (info["l1_size"], info["l1_size"] * span, self.size))
        if info["l1_off"] % self._cluster or info["l1_off"] + 8 * n > file_size:
            raise QcowError(_t("qcow2.l1_unreadable"))
        raw = self._file_read(info["l1_off"], 8 * n)
        if len(raw) < 8 * n:
            raise QcowError(_t("qcow2.l1_unreadable"))
        table = array.array("Q")
        table.frombytes(raw)
        if sys.byteorder == "little":
            table.byteswap()
        self._l1 = table
        self._l2 = {}
        self._clusters = {}
        self._noted = set()
        if info["snapshots"]:
            self.findings.append(
                "The image holds %d internal snapshot(s). Only the current "
                "state of the disk is read, not the snapshots."
                % info["snapshots"])
        self.bytes_per_sector = 512

    def _note_once(self, key, text):
        if key not in self._noted:
            self._noted.add(key)
            self.findings.append(text)

    def _file_read(self, offset, length):
        if offset < 0 or length <= 0 or offset >= self._file_size:
            return b""
        length = min(length, self._file_size - offset)
        with self._io_lock:
            self._fh.seek(offset)
            return self._fh.read(length)

    def _l2_table(self, index):
        got = self._l2.get(index)
        if got is not None:
            return got
        entry = self._l1[index] if index < len(self._l1) else 0
        off = entry & _OFFSET_MASK
        if not off:
            table = None
        elif off % self._cluster or off + self._cluster > self._file_size:
            self._note_once(
                ("l2", index),
                "The L1 entry %d points at an L2 table at file offset %d, "
                "which is not a whole cluster inside the file; the range "
                "it covers reads as zeros." % (index, off))
            table = None
        else:
            raw = self._file_read(off, self._cluster)
            table = array.array("Q")
            table.frombytes(raw)
            if sys.byteorder == "little":
                table.byteswap()
        if len(self._l2) >= _L2_CACHE:
            self._l2.clear()
        self._l2[index] = table
        return table

    def _cluster_bytes(self, vindex):
        """The whole content of virtual cluster `vindex`."""
        l1, l2 = divmod(vindex, self._l2_entries)
        table = self._l2_table(l1)
        entry = table[l2] if table is not None else 0
        if entry & _COMPRESSED:
            return self._compressed(vindex, entry)
        off = entry & _OFFSET_MASK
        if not off or entry & _ZERO_FLAG:
            return None
        if off + self._cluster > self._file_size:
            self._note_once(
                ("cluster", vindex),
                "Cluster %d is recorded at file offset %d and runs past the "
                "end of the file; what is missing reads as zeros."
                % (vindex, off))
        data = self._file_read(off, self._cluster)
        return data + bytes(self._cluster - len(data))

    def _compressed(self, vindex, entry):
        got = self._clusters.get(vindex)
        if got is not None:
            return got
        shift = 62 - (self._bits - 8)
        host = entry & ((1 << shift) - 1)
        sectors = ((entry >> shift) & ((1 << (self._bits - 8)) - 1)) + 1
        length = sectors * 512 - (host & 511)
        blob = self._file_read(host, length)
        data, _over, _status = inflate_ended(blob, self._cluster,
                                           wbits=-zlib.MAX_WBITS)
        # The stream may stop before its end marker once a cluster's worth
        # is out; too little output is the damaged case.
        if len(data) < self._cluster:
            self._note_once(
                ("comp", vindex),
                "Compressed cluster %d would not inflate to a whole "
                "cluster; the part that did is used and the rest reads as "
                "zeros." % vindex)
            data += bytes(self._cluster - len(data))
        if len(self._clusters) >= _CLUSTER_CACHE:
            self._clusters.clear()
        self._clusters[vindex] = data
        return data

    def read_at(self, offset, length):
        if offset < 0 or offset >= self.size or length <= 0:
            return b""
        length = min(length, self.size - offset)
        out = bytearray()
        while length > 0:
            vindex, within = divmod(offset, self._cluster)
            n = min(length, self._cluster - within)
            data = self._cluster_bytes(vindex)
            out += bytes(n) if data is None else data[within:within + n]
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
                "note": _t("qcow2.qcow2_stores_acquisition_hash")}

    def info(self):
        h = self.header
        acquisition = {
            "container size on disk": self._file_size,
            "version": h["version"],
            "cluster size": self._cluster,
            "internal snapshots": h["snapshots"],
        }
        return {
            "format": "QEMU disk (QCOW2, version %d)" % h["version"],
            "segments": [os.path.basename(self.path)],
            "size": self.size,
            "bytes_per_sector": self.bytes_per_sector,
            "chunk_size": self._cluster,
            "acquisition": acquisition,
            "findings": list(self.findings),
        }
