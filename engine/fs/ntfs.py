from .streams import NoSuchStream
import struct
import datetime
import threading

from . import lznt1

STANDARD_INFORMATION = 0x10
ATTRIBUTE_LIST = 0x20
FILE_NAME = 0x30
VOLUME_NAME = 0x60
DATA = 0x80
BITMAP = 0xB0

ATTR_NAMES = {
    0x10: "$STANDARD_INFORMATION", 0x20: "$ATTRIBUTE_LIST", 0x30: "$FILE_NAME",
    0x40: "$OBJECT_ID", 0x50: "$SECURITY_DESCRIPTOR", 0x60: "$VOLUME_NAME",
    0x70: "$VOLUME_INFORMATION", 0x80: "$DATA", 0x90: "$INDEX_ROOT",
    0xA0: "$INDEX_ALLOCATION", 0xB0: "$BITMAP", 0xC0: "$REPARSE_POINT",
    0x100: "$LOGGED_UTILITY_STREAM",
}

SYSTEM_FILES = {
    0: "$MFT", 1: "$MFTMirr", 2: "$LogFile", 3: "$Volume", 4: "$AttrDef",
    5: ".", 6: "$Bitmap", 7: "$Boot", 8: "$BadClus", 9: "$Secure",
    10: "$UpCase", 11: "$Extend",
}

_FILETIME_CACHE = {}

def filetime(v):
    if not v:
        return None
    hit = _FILETIME_CACHE.get(v)
    if hit is not None:
        return hit
    try:
        out = (datetime.datetime(1601, 1, 1)
               + datetime.timedelta(microseconds=v // 10)).isoformat() + "Z"
    except (OverflowError, ValueError):
        return None
    if len(_FILETIME_CACHE) < 400000:
        _FILETIME_CACHE[v] = out
    return out

def apply_fixups(buf, sector_size):
    if len(buf) < 8:
        return buf, False
    usa_off, usa_count = struct.unpack("<HH", buf[4:8])
    if usa_count == 0 or usa_off + usa_count * 2 > len(buf):
        return buf, False
    usn = buf[usa_off:usa_off + 2]
    b = bytearray(buf)
    ok = True
    for i in range(1, usa_count):
        end = i * sector_size - 2
        if end + 2 > len(b):
            break
        if bytes(b[end:end + 2]) != usn:
            ok = False
        b[end:end + 2] = buf[usa_off + i * 2: usa_off + i * 2 + 2]
    return bytes(b), ok

RUN_TOO_LONG = ("A data run claimed more clusters than the volume holds. "
                "That run and everything after it in the same run list was "
                "not read — those files are incomplete here.")

RUN_OUT_OF_VOLUME = ("A data run pointed outside the volume. That run and "
                     "everything after it in the same run list was not read "
                     "— those files are incomplete here.")

MFT_RECORDS_CLAMPED = ("The $MFT's run list claims more records than the "
                       "image holds. The record count was clamped to the "
                       "image — records beyond it are not read here.")

def _note(findings, text):
    if findings is not None and text not in findings:
        findings.append(text)

def decode_runlist(data, cluster_count=None, findings=None):
    runs = []
    i = 0
    lcn = 0
    while i < len(data):
        head = data[i]
        if head == 0:
            break
        len_size = head & 0x0F
        off_size = (head >> 4) & 0x0F
        i += 1
        if len_size == 0 or i + len_size + off_size > len(data):
            break
        length = int.from_bytes(data[i:i + len_size], "little", signed=False)
        i += len_size
        if off_size:
            # A run list is a chain of deltas, so one bogus entry poisons
            # every entry after it. Stop at the first one rather than carry
            # on from a base we no longer trust. Only a run that occupies
            # clusters is bounded by the volume: a sparse run is a hole, and
            # a sparse file's holes may add up to more than the volume holds.
            if cluster_count and length > cluster_count:
                _note(findings, RUN_TOO_LONG)
                break
            delta = int.from_bytes(data[i:i + off_size], "little", signed=True)
            i += off_size
            lcn += delta
            if lcn < 0 or (cluster_count and lcn + length > cluster_count):
                _note(findings, RUN_OUT_OF_VOLUME)
                break
            runs.append((lcn, length))
        else:
            runs.append((None, length))
    return runs

class Attribute:
    def __init__(self, type_id, name, resident, header, body, runs=None,
                 alloc_size=0, real_size=0, flags=0, start_vcn=0,
                 compression_unit=0, init_size=None):
        self.type_id = type_id
        self.name = name
        self.resident = resident
        self.body = body
        self.runs = runs or []
        self.alloc_size = alloc_size
        self.real_size = real_size
        self.flags = flags
        self.start_vcn = start_vcn
        self.compression_unit = compression_unit
        self._init_size = init_size

    @property
    def init_size(self):
        """Valid data length: bytes from here to real_size were never
        written, and read as zeros whatever the clusters hold. Only the
        first extent declares one; without it the whole file is valid."""
        if self._init_size is None:
            return self.real_size
        return max(0, min(self._init_size, self.real_size))

    @property
    def type_name(self):
        return ATTR_NAMES.get(self.type_id, "0x%X" % self.type_id)

    @property
    def compressed(self):
        return bool(self.flags & 0x0001)

    @property
    def encrypted(self):
        return bool(self.flags & 0x4000)

    @property
    def sparse(self):
        return bool(self.flags & 0x8000)

class MftRecord:
    def __init__(self, number, buf, fs, follow_list=True):
        self.number = number
        self.valid = False
        self.in_use = False
        self.is_dir = False
        self.attrs = []
        self.parent = None
        self.names = []
        self.si = {}
        self.fs = fs
        self.fixup_ok = True
        self.base_reference = 0
        self._follow_list = follow_list
        self._parse(buf)

    def _parse(self, buf):
        if len(buf) < 48 or buf[0:4] != b"FILE":
            return
        buf, self.fixup_ok = apply_fixups(buf, self.fs.bytes_per_sector)
        (lsn,) = struct.unpack("<Q", buf[8:16])
        seq, link_count, attr_off, flags = struct.unpack("<HHHH", buf[16:24])
        used, alloc = struct.unpack("<II", buf[24:32])
        self.base_reference = struct.unpack("<Q", buf[32:40])[0] & 0xFFFFFFFFFFFF
        self.sequence = seq
        self.link_count = link_count
        self.lsn = lsn
        self.in_use = bool(flags & 0x01)
        self.is_dir = bool(flags & 0x02)
        self.valid = True

        off = attr_off
        guard = 0
        while off + 4 <= len(buf) and guard < 512:
            guard += 1
            type_id = struct.unpack("<I", buf[off:off + 4])[0]
            if type_id == 0xFFFFFFFF:
                break
            if off + 16 > len(buf):
                break
            length = struct.unpack("<I", buf[off + 4:off + 8])[0]
            if length < 16 or off + length > len(buf):
                break
            non_res = buf[off + 8]
            name_len = buf[off + 9]
            name_off = struct.unpack("<H", buf[off + 10:off + 12])[0]
            attr_flags = struct.unpack("<H", buf[off + 12:off + 14])[0]
            name = ""
            if name_len:
                name = buf[off + name_off: off + name_off + name_len * 2] \
                    .decode("utf-16-le", "replace")
            if non_res:
                start_vcn, last_vcn = struct.unpack("<QQ", buf[off + 16:off + 32])
                run_off = struct.unpack("<H", buf[off + 32:off + 34])[0]
                comp_unit = struct.unpack("<H", buf[off + 34:off + 36])[0]
                alloc_size, real_size = struct.unpack("<QQ", buf[off + 40:off + 56])
                init_size = (struct.unpack("<Q", buf[off + 56:off + 64])[0]
                             if length >= 64 else None)
                runs = decode_runlist(buf[off + run_off: off + length],
                                      getattr(self.fs, "cluster_count", 0),
                                      getattr(self.fs, "findings", None))
                # Sizes are meaningful only in an attribute's first extent.
                a = Attribute(type_id, name, False, None, None, runs,
                              alloc_size, real_size, attr_flags, start_vcn,
                              comp_unit,
                              init_size if start_vcn == 0 else None)
            else:
                content_len = struct.unpack("<I", buf[off + 16:off + 20])[0]
                content_off = struct.unpack("<H", buf[off + 20:off + 22])[0]
                body = buf[off + content_off: off + content_off + content_len]
                a = Attribute(type_id, name, True, None, body,
                              real_size=len(body), flags=attr_flags)
            self.attrs.append(a)
            self._interpret(a)
            off += length

        if self._follow_list:
            self._follow_attribute_list()

    def _follow_attribute_list(self):
        listing = next((a for a in self.attrs if a.type_id == ATTRIBUTE_LIST),
                       None)
        if listing is None or self.fs is None:
            return
        try:
            if listing.resident:
                body = listing.body
            else:
                got = bytearray()
                for ext in self.fs.attribute_extents(listing):
                    if ext["offset"] is None:
                        got += bytes(ext["length"])
                    else:
                        got += self.fs.source.read_at(ext["offset"],
                                                      ext["length"])
                    if len(got) >= listing.real_size:
                        break
                body = bytes(got[:listing.real_size])
        except Exception:
            return
        if not body:
            return

        wanted = {}
        pos = 0
        guard = 0
        while pos + 26 <= len(body) and guard < 4096:
            guard += 1
            type_id, entry_len = struct.unpack_from("<IH", body, pos)
            if entry_len < 26 or pos + entry_len > len(body):
                break
            name_len = body[pos + 6]
            name_off = body[pos + 7]
            start_vcn = struct.unpack_from("<Q", body, pos + 8)[0]
            ref = struct.unpack_from("<Q", body, pos + 16)[0] & 0xFFFFFFFFFFFF
            name = ""
            if name_len:
                name = body[pos + name_off:
                            pos + name_off + name_len * 2].decode(
                                "utf-16-le", "replace")
            if ref != self.number:
                wanted.setdefault((type_id, name), []).append((start_vcn, ref))
            pos += entry_len

        records = {}
        for entries in wanted.values():
            for _vcn, ref in entries:
                if ref in records:
                    continue
                try:
                    records[ref] = self.fs.record(ref, cache=False,
                                                  follow_list=False)
                except Exception:
                    records[ref] = None

        for (type_id, name), entries in wanted.items():
            have = next((a for a in self.attrs
                         if a.type_id == type_id and a.name == name), None)
            pieces = []
            for _vcn, ref in sorted(entries):
                rec = records.get(ref)
                if not rec:
                    continue
                for a in rec.attrs:
                    if a.type_id == type_id and a.name == name:
                        pieces.append(a)
            if not pieces:
                continue
            if have is None:
                pieces.sort(key=lambda a: a.start_vcn)
                first = pieces[0]
                merged = Attribute(
                    first.type_id, first.name, first.resident, None,
                    first.body, list(first.runs), first.alloc_size,
                    first.real_size, first.flags, first.start_vcn,
                    first.compression_unit, first._init_size)
                for extra in pieces[1:]:
                    merged.runs.extend(extra.runs)
                    merged.real_size = max(merged.real_size, extra.real_size)
                    merged.alloc_size = max(merged.alloc_size, extra.alloc_size)
                self.attrs.append(merged)
                self._interpret(merged)
            else:
                for extra in sorted(pieces, key=lambda a: a.start_vcn):
                    if extra.start_vcn > have.start_vcn:
                        have.runs.extend(extra.runs)
                        have.real_size = max(have.real_size, extra.real_size)
                        have.alloc_size = max(have.alloc_size, extra.alloc_size)

    def _interpret(self, a):
        if a.type_id == STANDARD_INFORMATION and a.resident and len(a.body) >= 48:
            c, m, mft, acc = struct.unpack("<QQQQ", a.body[0:32])
            self.si = {
                "created": filetime(c), "modified": filetime(m),
                "mft_modified": filetime(mft), "accessed": filetime(acc),
                "flags": struct.unpack("<I", a.body[32:36])[0],
            }
        elif a.type_id == FILE_NAME and a.resident and len(a.body) >= 66:
            parent = struct.unpack("<Q", a.body[0:8])[0] & 0xFFFFFFFFFFFF
            c, m, mft, acc = struct.unpack("<QQQQ", a.body[8:40])
            alloc, real = struct.unpack("<QQ", a.body[40:56])
            nlen = a.body[64]
            namespace = a.body[65]
            nm = a.body[66:66 + nlen * 2].decode("utf-16-le", "replace")
            self.names.append({"name": nm, "namespace": namespace,
                               "parent": parent, "size": real,
                               "fn_created": filetime(c), "fn_modified": filetime(m),
                               "fn_mft_modified": filetime(mft),
                               "fn_accessed": filetime(acc)})
            if self.parent is None or namespace != 2:
                self.parent = parent

    def best_name(self):
        if not self.names:
            return SYSTEM_FILES.get(self.number, "<%d>" % self.number)
        for ns in (3, 1, 0, 2):
            for n in self.names:
                if n["namespace"] == ns:
                    return n["name"]
        return self.names[0]["name"]

    def data_attrs(self):
        return [a for a in self.attrs if a.type_id == DATA]

    def size(self):
        for a in self.data_attrs():
            if a.name == "":
                return a.real_size if not a.resident else len(a.body)
        return 0

class NtfsFS:
    name = "NTFS"
    root_node = 5

    def __init__(self, source):
        self.source = source
        b = source.read_at(0, 512)
        if len(b) < 512 or b[3:11] != b"NTFS    ":
            raise ValueError("Not an NTFS volume boot record.")
        self.bytes_per_sector = struct.unpack("<H", b[11:13])[0]
        self.sectors_per_cluster = b[13]
        if self.sectors_per_cluster > 0x80:
            self.sectors_per_cluster = 1 << (256 - self.sectors_per_cluster)
        self.cluster_size = self.bytes_per_sector * self.sectors_per_cluster
        self.total_sectors = struct.unpack("<Q", b[40:48])[0]
        # Bound for run-list sanity checks. The boot record is as untrusted as
        # anything else on the image, so take the smaller of what it claims and
        # what the reader underneath us actually holds.
        limits = []
        if self.sectors_per_cluster:
            limits.append(self.total_sectors // self.sectors_per_cluster)
        src_size = getattr(source, "size", 0) or 0
        if src_size and self.cluster_size:
            limits.append(src_size // self.cluster_size)
        self.cluster_count = min([n for n in limits if n] or [0])
        self.mft_cluster = struct.unpack("<Q", b[48:56])[0]
        self.mftmirr_cluster = struct.unpack("<Q", b[56:64])[0]
        raw_rec = struct.unpack("<b", b[64:65])[0]
        self.record_size = (1 << -raw_rec) if raw_rec < 0 else raw_rec * self.cluster_size
        raw_idx = struct.unpack("<b", b[68:69])[0]
        self.index_size = (1 << -raw_idx) if raw_idx < 0 else raw_idx * self.cluster_size
        self.serial = struct.unpack("<Q", b[72:80])[0]
        if not 128 <= self.record_size <= 65536:
            self.record_size = 1024

        self.findings = []
        self.mft_offset = self.mft_cluster * self.cluster_size
        self.data_offset = 0
        self._mft_runs = None
        self._cache = {}
        self._tree = None
        self._tree_lock = threading.Lock()
        self._tree_progress = 0.0
        self.tree_store = None
        self._load_mft_runs()

    def _load_mft_runs(self):
        buf = self.source.read_at(self.mft_offset, self.record_size)
        rec = MftRecord(0, buf, self)
        runs = []
        for a in rec.data_attrs():
            if a.name == "" and not a.resident:
                runs = a.runs
                self.mft_size = a.real_size
                break
        self._mft_runs = runs or [(self.mft_cluster,
                                   max(1, min(1 << 20, self.cluster_count)))]
        self.record_count = sum(l for _, l in self._mft_runs) \
            * self.cluster_size // self.record_size
        src_size = getattr(self.source, "size", 0) or 0
        if src_size:
            most = src_size // self.record_size
            if self.record_count > most:
                _note(self.findings, MFT_RECORDS_CLAMPED)
                self.record_count = most

    def _record_offset(self, n):
        target = n * self.record_size
        pos = 0
        for lcn, length in self._mft_runs:
            span = length * self.cluster_size
            if pos + span > target:
                if lcn is None:
                    return None
                return lcn * self.cluster_size + (target - pos)
            pos += span
        return None

    def record(self, n, cache=True, follow_list=True):
        if n in self._cache:
            return self._cache[n]
        off = self._record_offset(n)
        if off is None:
            return None
        buf = self.source.read_at(off, self.record_size)
        if len(buf) < self.record_size:
            return None
        rec = MftRecord(n, buf, self, follow_list=follow_list)
        rec.record_offset = off
        if cache and rec.valid and len(self._cache) < 200000:
            self._cache[n] = rec
        return rec if rec.valid else None

    def attribute_extents(self, attr):
        out = []
        remaining = attr.real_size
        for lcn, length in attr.runs:
            span = length * self.cluster_size
            entry = {"offset": None if lcn is None else lcn * self.cluster_size,
                     "length": span, "sparse": lcn is None,
                     "cluster": lcn, "clusters": length}
            entry["used"] = min(span, remaining) if remaining > 0 else 0
            out.append(entry)
            remaining -= span
        return out

    def _expand_runs(self, runs):
        # One entry per cluster, so this has to stay bounded by the volume
        # even if a run list slipped past decode_runlist.
        cap = self.cluster_count or (1 << 32)
        out = []
        for lcn, length in runs:
            length = max(0, min(length, cap - len(out)))
            if lcn is None:
                out.extend([None] * length)
            else:
                out.extend(range(lcn, lcn + length))
            if len(out) >= cap:
                break
        return out

    def read_compressed(self, attr, max_bytes=None):
        limit = attr.real_size if max_bytes is None \
            else min(attr.real_size, max_bytes)
        return self.read_compressed_range(attr, 0, limit)

    def _compression_unit(self, attr, unit, vcns, cu_clusters, want):
        base = unit * cu_clusters
        block = vcns[base:base + cu_clusters]
        allocated = [c for c in block if c is not None]
        if not allocated:
            return b"\x00" * want
        if len(allocated) == cu_clusters:
            return self._read_clusters(allocated, want)
        raw = self._read_clusters(allocated, len(allocated) * self.cluster_size)
        try:
            return lznt1.decompress(raw, want)
        except Exception:
            self.findings.append(
                "Compression unit %d of a $DATA attribute failed to "
                "decode; zero-filled." % unit)
            return b"\x00" * want

    def read_compressed_range(self, attr, offset, length):
        cu_clusters = 1 << (attr.compression_unit or 4)
        cu_bytes = cu_clusters * self.cluster_size
        end = min(offset + length, attr.real_size)
        if offset < 0 or offset >= end or cu_bytes <= 0:
            return b""
        # Kept on the attribute: a file read a piece at a time would
        # otherwise rebuild the whole cluster map for every piece.
        vcns = getattr(attr, "_vcns", None)
        if vcns is None or attr._vcns_runs != len(attr.runs):
            vcns = attr._vcns = self._expand_runs(attr.runs)
            attr._vcns_runs = len(attr.runs)
        out = bytearray()
        unit = offset // cu_bytes
        pos = unit * cu_bytes
        while pos < end:
            if unit * cu_clusters >= len(vcns):
                break
            want = min(cu_bytes, attr.real_size - pos)
            if want <= 0:
                break
            chunk = self._compression_unit(attr, unit, vcns, cu_clusters, want)
            lo = max(offset, pos) - pos
            hi = min(end, pos + want) - pos
            out += chunk[lo:hi]
            pos += want
            unit += 1
        return bytes(out)

    def _read_clusters(self, clusters, want):
        out = bytearray()
        i = 0
        while i < len(clusters) and len(out) < want:
            j = i
            while j + 1 < len(clusters) and clusters[j + 1] == clusters[j] + 1:
                j += 1
            n = (j - i + 1) * self.cluster_size
            out += self.source.read_at(clusters[i] * self.cluster_size,
                                       min(n, want - len(out)))
            i = j + 1
        return bytes(out)

    def attr_extents(self, attr):
        if attr.resident or attr.compressed:
            return
        vcn = 0
        end = attr.real_size
        for lcn, length in attr.runs:
            start = vcn * self.cluster_size
            span = length * self.cluster_size
            vcn += length
            if lcn is None or start >= end:
                continue
            yield start, lcn * self.cluster_size, min(span, end - start)

    @staticmethod
    def _past_valid_data(attr, offset, data):
        """data (read from `offset`) with every byte at or past the valid
        data length replaced by zeros, as Windows returns them."""
        cut = attr.init_size - offset
        if attr.resident or cut >= len(data):
            return data
        cut = max(0, cut)
        return data[:cut] + bytes(len(data) - cut)

    def read_attr_range(self, attr, offset, length):
        return self._past_valid_data(
            attr, offset, self._read_attr_range(attr, offset, length))

    def _read_attr_range(self, attr, offset, length):
        if attr.resident:
            return attr.body[offset:offset + length]
        if attr.compressed:
            return self.read_compressed_range(attr, offset, length)
        out = bytearray()
        want_end = min(offset + length, attr.real_size)
        vcn = 0
        for lcn, n in attr.runs:
            start = vcn * self.cluster_size
            span = n * self.cluster_size
            vcn += n
            if start + span <= offset:
                continue
            if start >= want_end:
                break
            lo = max(offset, start)
            hi = min(want_end, start + span)
            if lcn is None:
                out += b"\x00" * (hi - lo)
            else:
                out += self.source.read_at(lcn * self.cluster_size + (lo - start),
                                           hi - lo)
        return bytes(out)

    def read_attr(self, attr, max_bytes=None):
        return self._past_valid_data(attr, 0,
                                     self._read_attr(attr, max_bytes))

    def _read_attr(self, attr, max_bytes=None):
        if attr.resident:
            return attr.body if max_bytes is None else attr.body[:max_bytes]
        if attr.compressed:
            return self.read_compressed(attr, max_bytes)
        limit = attr.real_size if max_bytes is None else min(attr.real_size, max_bytes)
        out = bytearray()
        for lcn, length in attr.runs:
            need = limit - len(out)
            if need <= 0:
                break
            span = length * self.cluster_size
            if lcn is None:
                out += b"\x00" * min(span, need)
            else:
                out += self.source.read_at(lcn * self.cluster_size,
                                           min(span, need))
        return bytes(out[:limit])

    def read_file(self, entry, max_bytes=None, stream=""):
        rec = self.record(entry["mft"])
        if not rec:
            return b""
        for a in rec.data_attrs():
            if a.name == stream:
                return self.read_attr(a, max_bytes)
        if stream:
            raise NoSuchStream(entry.get("name"), stream,
                               [a.name for a in rec.data_attrs() if a.name])
        return b""

    def read_range(self, entry, off, length, stream=""):
        rec = self.record(entry["mft"])
        if not rec:
            return b""
        for a in rec.data_attrs():
            if a.name == stream:
                return self.read_attr_range(a, off, length)
        if stream:
            raise NoSuchStream(entry.get("name"), stream,
                               [a.name for a in rec.data_attrs() if a.name])
        return b""

    def streams(self, entry):
        rec = self.record(entry["mft"])
        if not rec:
            return []
        out = []
        for a in rec.data_attrs():
            out.append({
                "name": a.name,
                "size": a.real_size if not a.resident else len(a.body),
                "resident": a.resident,
                "compressed": a.compressed,
                "encrypted": a.encrypted,
                "sparse": a.sparse,
                "default": a.name == "",
            })
        return out

    def index_pending(self):
        return self._tree is None

    def build_tree(self, limit=None, progress=None):
        if self._tree is not None:
            return self._tree
        if self.tree_store is not None:
            got = self.tree_store[0]()
            if got is not None:
                self._tree = got
                return self._tree
        while not self._tree_lock.acquire(timeout=0.2):
            if progress is not None:
                progress(self._tree_progress)
        try:
            if self._tree is not None:
                return self._tree
            return self._build_tree_locked(limit, progress)
        finally:
            self._tree_lock.release()

    def _build_tree_locked(self, limit, progress):
        nodes, children = {}, {}
        total = int(self.record_count if limit is None
                    else min(limit, self.record_count))
        step = max(1, total // 200)
        for n in range(total):
            if n % step == 0:
                self._tree_progress = n / total
                if progress is not None:
                    progress(n / total)
            rec = self.record(n, cache=False)
            if not rec:
                continue
            name = rec.best_name()
            streams = []
            for a in rec.data_attrs():
                if a.name:
                    streams.append({"name": a.name,
                                    "size": a.real_size if not a.resident
                                    else len(a.body)})
            node = {
                "mft": n, "name": name, "is_dir": rec.is_dir,
                "deleted": not rec.in_use, "size": rec.size(),
                "parent": rec.parent if rec.parent is not None else 5,
                "created": rec.si.get("created"),
                "modified": rec.si.get("modified"),
                "accessed": rec.si.get("accessed"),
                "mft_modified": rec.si.get("mft_modified"),
                "resident": all(a.resident for a in rec.data_attrs()) or None,
                "streams": streams,
                "system": n < 16,
                "fixup_ok": rec.fixup_ok,
                "id": "mft:%d" % n,
            }
            if rec.names:
                node["fn_created"] = rec.names[0].get("fn_created")
                node["fn_modified"] = rec.names[0].get("fn_modified")
            nodes[n] = node
            children.setdefault(node["parent"], []).append(n)
        self._tree = (nodes, children)
        if self.tree_store is not None:
            self.tree_store[1](self._tree)
        return self._tree

    def listdir(self, mft_number=5, path="/"):
        nodes, children = self.build_tree()
        out = []
        for n in sorted(children.get(mft_number, [])):
            if n == mft_number:
                continue
            node = dict(nodes[n])
            node["path"] = path.rstrip("/") + "/" + node["name"]
            out.append(node)
        out.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
        return out

    def stat(self, entry, stream=""):
        rec = self.record(entry["mft"])
        if not rec:
            return {}
        info = {"filesystem": "NTFS", "cluster_size": self.cluster_size,
                "mft_record": entry["mft"], "sequence": rec.sequence,
                "link_count": rec.link_count,
                "record_offset": getattr(rec, "record_offset", None),
                "attributes": [], "names": rec.names,
                "streams": self.streams(entry)}
        if stream:
            info["stream"] = stream
        for a in rec.attrs:
            item = {"type": a.type_name, "name": a.name, "resident": a.resident,
                    "size": a.real_size, "compressed": a.compressed,
                    "encrypted": a.encrypted, "sparse": a.sparse}
            if a.compressed:
                item["compression_unit_clusters"] = 1 << (a.compression_unit or 4)
            if not a.resident:
                item["runs"] = self.attribute_extents(a)
            info["attributes"].append(item)
        want = stream or ""
        found = False
        for a in rec.data_attrs():
            if a.name == want:
                found = True
            if a.name == want and not a.resident:
                info["runs"] = self.attribute_extents(a)
                if a.real_size % self.cluster_size:
                    last = [r for r in info["runs"] if not r["sparse"]]
                    if last:
                        used_in_last = a.real_size % self.cluster_size
                        tail = last[-1]
                        info["slack"] = {
                            "offset": tail["offset"] + tail["length"] - (
                                self.cluster_size - used_in_last),
                            "length": self.cluster_size - used_in_last}
        if stream and not found:
            info["stream_missing"] = True
            info.pop("runs", None)
            info.pop("slack", None)
            return info
        for a in rec.data_attrs():
            if a.name == want and a.compressed:
                info["runs_compressed"] = True
                info["note"] = (
                    "Attribute is LZNT1 compressed in %d-cluster units. The "
                    "runs below point at compressed bytes — the hex view will "
                    "not show file content at those offsets, and carving will "
                    "not recognise it. Use the extracted content instead."
                    % (1 << (a.compression_unit or 4)))
            if a.name == want and a.encrypted:
                info["note"] = ("Attribute is EFS encrypted. The runs point at "
                                "ciphertext; this build does not decrypt.")
        for a in rec.data_attrs():
            if a.name == want and not a.resident and \
                    a.init_size < a.real_size:
                info["valid_data_length"] = a.init_size
                info["note"] = ((info["note"] + " ") if info.get("note")
                                else "") + (
                    "Valid data length (%d) is shorter than the file size "
                    "(%d). Bytes after it were never written by this file and "
                    "read as zeros, as Windows returns them; the clusters "
                    "there still hold whatever was on disk before, which the "
                    "runs below point at." % (a.init_size, a.real_size))
        if entry.get("deleted"):
            info["recovery"] = ("Record marked not-in-use. Runlist is intact "
                                "but clusters may have been reallocated; "
                                "verify content before relying on it.")
        return info

    def info(self):
        rec = self.record(3)
        label = ""
        if rec:
            for a in rec.attrs:
                if a.type_id == VOLUME_NAME and a.resident:
                    label = a.body.decode("utf-16-le", "replace")
        return {
            "type": "NTFS", "label": label,
            "bytes_per_sector": self.bytes_per_sector,
            "sectors_per_cluster": self.sectors_per_cluster,
            "cluster_size": self.cluster_size,
            "total_sectors": self.total_sectors,
            "mft_offset": self.mft_offset,
            "mft_record_size": self.record_size,
            "mft_records": int(self.record_count),
            "serial": "%016X" % self.serial,
        }

    def allocated_extents(self):
        nodes, _ = self.build_tree()
        out = []
        for n, node in nodes.items():
            if node["deleted"] or node["is_dir"]:
                continue
            rec = self.record(n, cache=False)
            if not rec:
                continue
            for a in rec.data_attrs():
                if not a.resident:
                    for r in self.attribute_extents(a):
                        if not r["sparse"]:
                            out.append((r["offset"], r["offset"] + r["length"]))
        return out

class EncryptedVolume(ValueError):

    def __init__(self, kind):
        self.kind = kind
        super().__init__(
            "This volume is encrypted with %s. Unlock it to read its "
            "contents." % kind)

ENCRYPTED_SIGS = (
    (3, b"-FVE-FS-", "BitLocker"),
    (0, b"LUKS\xba\xbe", "LUKS"),
)

def open_fs(source):
    from . import fat, exfat, ext4, apfs, hfsplus, ad1fs
    from .. import ad1 as ad1_mod
    b = source.read_at(0, 512)
    if ad1_mod.looks_like_ad1(b):
        return ad1fs.Ad1FS(source)
    for at, sig, kind in ENCRYPTED_SIGS:
        if b[at:at + len(sig)] == sig:
            raise EncryptedVolume(kind)
    if len(b) >= 11:
        if b[3:11] == b"NTFS    ":
            return NtfsFS(source)
        if b[3:11] == b"EXFAT   ":
            return exfat.ExfatFS(source)
    if source.read_at(1024 + 56, 2) == b"\x53\xEF":
        return ext4.Ext4FS(source)
    if hfsplus.detect(source):
        return hfsplus.open_volume(source)
    if apfs.looks_like_apfs(source):
        return apfs.ApfsContainer(source).default_volume()
    try:
        return fat.FatFS(source)
    except Exception:
        pass
    raise ValueError("No supported filesystem found at this offset.")
