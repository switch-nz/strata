from .streams import UnsupportedStream
from .ranges import read_runs
import datetime
import struct

ENTRY_BITMAP = 0x81
ENTRY_LABEL = 0x83
ENTRY_FILE = 0x85
ENTRY_STREAM = 0xC0
ENTRY_NAME = 0xC1

IN_USE = 0x80
MAX_DIR_BYTES = 256 << 20       # the largest directory exFAT allows

def _ts(packed, tenths=0, tz=0):
    """Decode a DOS-style timestamp. ``tz`` is the entry's UtcOffset byte
    (spec 7.4.10): bit 7 OffsetValid, bits 0-6 a signed offset in 15-minute
    units, signed-decimal per Table 31 (0x01 = +00:15, 0x7F = -00:15).  The
    timestamp is local time; the honest UTC rendering subtracts it. With no
    valid offset the zone is unknown, so the time is returned as recorded,
    without a "Z": whether it is UTC or local is for the examiner to judge."""
    if not packed:
        return None
    try:
        y = 1980 + ((packed >> 25) & 0x7F)
        mo = (packed >> 21) & 0x0F
        d = (packed >> 16) & 0x1F
        h = (packed >> 11) & 0x1F
        mi = (packed >> 5) & 0x3F
        s = (packed & 0x1F) * 2 + tenths // 100
        dt = datetime.datetime(y, mo, d, h, mi, min(s, 59))
        if not tz & 0x80:
            return dt.isoformat()
        dt -= datetime.timedelta(minutes=(tz & 0x40 and (tz & 0x3F) - 64
                                          or (tz & 0x3F)) * 15)
        return dt.isoformat() + "Z"
    except ValueError:
        return None

class ExfatFS:
    name = "exFAT"
    root_node = 0

    def __init__(self, source):
        self.source = source
        b = source.read_at(0, 512)
        if len(b) < 512 or b[3:11] != b"EXFAT   ":
            raise ValueError("Not an exFAT volume boot record.")
        self.partition_offset = struct.unpack("<Q", b[64:72])[0]
        self.volume_length = struct.unpack("<Q", b[72:80])[0]
        self.fat_offset = struct.unpack("<I", b[80:84])[0]
        self.fat_length = struct.unpack("<I", b[84:88])[0]
        self.heap_offset = struct.unpack("<I", b[88:92])[0]
        self.cluster_count = struct.unpack("<I", b[92:96])[0]
        self.root_cluster = struct.unpack("<I", b[96:100])[0]
        self.serial = struct.unpack("<I", b[100:104])[0]
        self.revision = struct.unpack("<H", b[104:106])[0]
        self.flags = struct.unpack("<H", b[106:108])[0]
        bps_shift, spc_shift = b[108], b[109]
        if not (9 <= bps_shift <= 12) or spc_shift > 25:
            raise ValueError("Implausible exFAT sector/cluster shift.")
        self.bytes_per_sector = 1 << bps_shift
        self.sectors_per_cluster = 1 << spc_shift
        self.cluster_size = self.bytes_per_sector * self.sectors_per_cluster
        self.num_fats = b[110]
        self.percent_in_use = b[112]
        self.dirty = bool(self.flags & 0x02)

        self.data_offset = self.heap_offset * self.bytes_per_sector
        self._fat = None
        self._bitmap = None
        self.label = ""
        self._bitmap_start = None
        self._bitmap_size = 0
        self.findings = []
        self._dir_streams = {}     # first cluster -> (contiguous, length)
        src_size = getattr(source, "size", 0) or 0
        if src_size and self.cluster_size:
            held = max(0, (src_size - self.data_offset) // self.cluster_size)
            if self.cluster_count > held:
                msg = ("Boot sector claims %d clusters but the image only "
                       "holds %d; trusting the image."
                       % (self.cluster_count, held))
                if msg not in self.findings:
                    self.findings.append(msg)
                self.cluster_count = held
        self._scan_root_metadata()

    def cluster_offset(self, n):
        return self.data_offset + (n - 2) * self.cluster_size

    def _load_fat(self):
        if self._fat is None:
            self._fat = self.source.read_at(
                self.fat_offset * self.bytes_per_sector,
                self.fat_length * self.bytes_per_sector)
        return self._fat

    def _fat_entry(self, n):
        fat = self._load_fat()
        i = n * 4
        if i + 4 > len(fat):
            return 0xFFFFFFFF
        return struct.unpack("<I", fat[i:i + 4])[0]

    def chain(self, start, contiguous=False, size=None):
        if contiguous:
            n = max(1, (size + self.cluster_size - 1) // self.cluster_size) \
                if size else 1
            limit = max(0, self.cluster_count + 2 - start)
            if n > limit:
                msg = ("Contiguous run from cluster %d truncated at "
                       "cluster heap end." % start)
                if msg not in self.findings:
                    self.findings.append(msg)
                n = limit
            # A range, not a list: a contiguous stream is exactly one run,
            # known analytically from its length, so nothing here should
            # cost memory proportional to the number of clusters. Slicing,
            # indexing, len() and iteration all still work for callers.
            return range(start, start + n)
        out, seen, c = [], set(), start
        while 2 <= c < self.cluster_count + 2 and c not in seen:
            seen.add(c)
            out.append(c)
            nxt = self._fat_entry(c)
            if nxt >= 0xFFFFFFF7 or nxt < 2:
                break
            c = nxt
        return out

    def _scan_root_metadata(self):
        data = self._read_dir_bytes(self.root_cluster, contiguous=False)
        for i in range(0, len(data) - 31, 32):
            e = data[i:i + 32]
            t = e[0]
            if t == 0:
                break
            if t == ENTRY_LABEL:
                n = e[1]
                self.label = e[2:2 + n * 2].decode("utf-16-le", "replace")
            elif t == ENTRY_BITMAP:
                self._bitmap_start = struct.unpack("<I", e[20:24])[0]
                self._bitmap_size = struct.unpack("<Q", e[24:32])[0]

    def _load_bitmap(self):
        if self._bitmap is None and self._bitmap_start:
            clusters = self.chain(self._bitmap_start)
            buf = bytearray()
            for c in clusters:
                buf += self.source.read_at(self.cluster_offset(c),
                                           self.cluster_size)
                if len(buf) >= self._bitmap_size:
                    break
            self._bitmap = bytes(buf[:self._bitmap_size])
        return self._bitmap or b""

    def _read_dir_bytes(self, cluster, contiguous=False, limit=None):
        if limit:
            limit = min(limit, MAX_DIR_BYTES)
        clusters = self.chain(cluster, contiguous, limit)
        buf = bytearray()
        for c in clusters[:MAX_DIR_BYTES // self.cluster_size]:
            block = self.source.read_at(self.cluster_offset(c),
                                        self.cluster_size)
            buf += block
            if limit and len(buf) >= limit:
                break
            if any(block[k] == 0 for k in range(0, len(block), 32)):
                break          # end-of-directory marker: nothing follows
        return bytes(buf)

    def _dir_stream(self, cluster):
        """How a directory's clusters are found: (contiguous, length) from
        its stream extension, or None to walk the FAT. The stream lives in
        the parent, so a directory not reached through its parent yet is
        looked for from the root down."""
        if cluster == self.root_cluster:
            return None
        if cluster not in self._dir_streams:
            stack, seen = [self.root_cluster], set()
            while stack and cluster not in self._dir_streams:
                c = stack.pop()
                if c in seen:
                    continue
                seen.add(c)
                try:
                    found = self._list(c, "/", self._dir_streams.get(c))
                except Exception:
                    continue
                stack.extend(e["start_cluster"] for e in found
                             if e["is_dir"] and not e["deleted"]
                             and e["start_cluster"])
        return self._dir_streams.get(cluster)

    def listdir(self, cluster=0, path="/"):
        cluster = cluster or self.root_cluster
        return self._list(cluster, path, self._dir_stream(cluster))

    def _list(self, cluster, path, dir_stream):
        if dir_stream and dir_stream[0]:
            data = self._read_dir_bytes(cluster, True, dir_stream[1])
        else:
            data = self._read_dir_bytes(cluster)
        base = self.cluster_offset(cluster)
        entries = []
        i = 0
        while i <= len(data) - 32:
            e = data[i:i + 32]
            t = e[0]
            if t == 0:
                break
            if (t & 0x7F) != (ENTRY_FILE & 0x7F):
                i += 32
                continue
            deleted = not (t & IN_USE)
            secondary = e[1]
            attrs = struct.unpack("<H", e[4:6])[0]
            created = _ts(struct.unpack("<I", e[8:12])[0], e[20], e[22])
            modified = _ts(struct.unpack("<I", e[12:16])[0], e[21], e[23])
            accessed = _ts(struct.unpack("<I", e[16:20])[0], tz=e[24])

            stream = None
            name_parts = []
            j = i + 32
            for _ in range(secondary):
                if j > len(data) - 32:
                    break
                s = data[j:j + 32]
                st = s[0] & 0x7F
                if st == (ENTRY_STREAM & 0x7F):
                    stream = {
                        "flags": s[1],
                        "name_length": s[3],
                        "valid_length": struct.unpack("<Q", s[8:16])[0],
                        "first_cluster": struct.unpack("<I", s[20:24])[0],
                        "length": struct.unpack("<Q", s[24:32])[0],
                    }
                elif st == (ENTRY_NAME & 0x7F):
                    name_parts.append(s[2:32].decode("utf-16-le", "replace"))
                j += 32
            i = j if secondary else i + 32
            if stream is None:
                continue

            name = "".join(name_parts)[:stream["name_length"]].rstrip("\x00")
            is_dir = bool(attrs & 0x10)
            first = stream["first_cluster"]
            if is_dir and first and (not deleted
                                     or first not in self._dir_streams):
                self._dir_streams[first] = (bool(stream["flags"] & 0x02),
                                            stream["length"])
            entries.append({
                "name": name or "<unnamed>",
                "path": path.rstrip("/") + "/" + name,
                "is_dir": is_dir,
                "deleted": deleted,
                "size": 0 if is_dir else stream["length"],
                "valid_size": stream["valid_length"],
                "start_cluster": stream["first_cluster"],
                "contiguous": bool(stream["flags"] & 0x02),
                "created": created, "modified": modified, "accessed": accessed,
                "attributes": self._attrs(attrs),
                "entry_offset": base + i,
                "id": "exfat:%d:%d" % (cluster, i),
            })
        entries.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
        return entries

    @staticmethod
    def _attrs(a):
        flags = [(0x01, "read-only"), (0x02, "hidden"), (0x04, "system"),
                 (0x10, "directory"), (0x20, "archive")]
        return [n for bit, n in flags if a & bit]

    def runs(self, entry):
        start = entry["start_cluster"]
        if not start:
            return []
        clusters = self.chain(start, entry.get("contiguous"), entry["size"])
        if not clusters:
            return []
        if isinstance(clusters, range):
            # Already one run end to end; nothing to walk cluster by
            # cluster to discover that.
            groups = [(clusters[0], len(clusters))]
        else:
            groups, rs, rl = [], clusters[0], 1
            for prev, cur in zip(clusters, clusters[1:]):
                if cur == prev + 1:
                    rl += 1
                else:
                    groups.append((rs, rl))
                    rs, rl = cur, 1
            groups.append((rs, rl))
        out, remaining = [], entry["size"]
        for c, n in groups:
            length = n * self.cluster_size
            out.append({"offset": self.cluster_offset(c), "length": length,
                        "used": max(0, min(length, remaining)),
                        "cluster": c, "clusters": n, "sparse": False})
            remaining -= length
        return out

    @staticmethod
    def _past_valid_data(entry, off, data):
        """data (read from `off`) with every byte at or past the stream's
        valid data length replaced by zeros, as the driver returns them."""
        valid = entry.get("valid_size")
        if valid is None or entry.get("is_dir"):
            return data
        cut = valid - off
        if cut >= len(data):
            return data
        cut = max(0, cut)
        return data[:cut] + bytes(len(data) - cut)

    def read_file(self, entry, max_bytes=None, stream=""):
        if stream:
            raise UnsupportedStream("exFAT", stream)
        size = entry["size"]
        if not entry.get("start_cluster") or not size:
            return b""
        limit = size if max_bytes is None else min(size, max_bytes)
        out = bytearray()
        for r in self.runs(entry):
            if len(out) >= limit:
                break
            out += self.source.read_at(r["offset"],
                                       min(r["length"], limit - len(out)))
        return self._past_valid_data(entry, 0, bytes(out[:limit]))

    def read_range(self, entry, off, length, stream=""):
        if stream:
            raise UnsupportedStream("exFAT", stream)
        size = entry["size"]
        if not entry.get("start_cluster") or not size:
            return b""
        return self._past_valid_data(
            entry, off, read_runs(self.source, self.runs(entry), off,
                                  min(length, max(0, size - off))))

    def slack(self, entry):
        if entry["is_dir"] or not entry["size"]:
            return None
        tail = entry["size"] % self.cluster_size
        if not tail:
            return None
        runs = self.runs(entry)
        if not runs:
            return None
        last = runs[-1]
        return {"offset": last["offset"] + last["length"]
                - (self.cluster_size - tail),
                "length": self.cluster_size - tail}

    def stat(self, entry):
        info = {"filesystem": "exFAT", "cluster_size": self.cluster_size,
                "contiguous": entry.get("contiguous")}
        if entry["is_dir"] and entry.get("start_cluster"):
            info["record_offset"] = self.cluster_offset(entry["start_cluster"])
        if not entry["is_dir"] and entry.get("start_cluster"):
            info["runs"] = self.runs(entry)
            info["slack"] = self.slack(entry)
            if entry.get("valid_size") is not None and \
                    entry["valid_size"] < entry["size"]:
                info["note"] = (
                    "Valid data length (%d) is shorter than the file size (%d). "
                    "Bytes after it were never written by this file and read "
                    "as zeros, as the driver returns them; the clusters there "
                    "still hold whatever was on disk before, which the runs "
                    "below point at." % (entry["valid_size"], entry["size"]))
            if entry.get("deleted"):
                info["recovery"] = (
                    "Directory entry deleted. This file was flagged contiguous, "
                    "so the extent is known exactly and no chain-walking guess "
                    "is involved — but the clusters may since have been reused. "
                    "Verify the content."
                    if entry.get("contiguous") else
                    "Directory entry deleted and the FAT chain released. "
                    "Content assumed contiguous from the start cluster; verify "
                    "before relying on it.")
        return info

    def info(self):
        return {
            "type": "exFAT", "label": self.label,
            "bytes_per_sector": self.bytes_per_sector,
            "sectors_per_cluster": self.sectors_per_cluster,
            "cluster_size": self.cluster_size,
            "cluster_count": self.cluster_count,
            "fat_count": self.num_fats,
            "first_data_offset": self.data_offset,
            "root_cluster": self.root_cluster,
            "serial": "%08X" % self.serial,
            "revision": "%d.%d" % (self.revision >> 8, self.revision & 0xFF),
            "percent_in_use": self.percent_in_use,
            "volume_dirty": self.dirty,
            "findings": self.findings,
        }

    def allocated_extents(self):
        out = []
        stack = [(self.root_cluster, "/")]
        seen = set()
        while stack:
            cluster, path = stack.pop()
            if cluster in seen:
                continue
            seen.add(cluster)
            try:
                entries = self.listdir(cluster, path)
            except Exception:
                continue
            for e in entries:
                if e["deleted"]:
                    continue
                if e["is_dir"]:
                    if e["start_cluster"]:
                        stack.append((e["start_cluster"], e["path"]))
                elif e["start_cluster"] and e["size"]:
                    for r in self.runs(e):
                        out.append((r["offset"], r["offset"] + r["length"]))
        if self._bitmap_start:
            for c in self.chain(self._bitmap_start):
                out.append((self.cluster_offset(c),
                            self.cluster_offset(c) + self.cluster_size))
        return out
