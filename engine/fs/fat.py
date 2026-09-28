import struct
import datetime

from .ranges import read_runs

def _dos_time(date, time_, tenths=0):
    # FAT records local time and no zone, so no "Z": nothing says it is UTC.
    if date == 0:
        return None
    try:
        y = 1980 + ((date >> 9) & 0x7F)
        mo = (date >> 5) & 0x0F
        d = date & 0x1F
        h = (time_ >> 11) & 0x1F
        mi = (time_ >> 5) & 0x3F
        s = (time_ & 0x1F) * 2 + tenths // 100
        return datetime.datetime(y, mo, d, h, mi, min(s, 59)).isoformat()
    except ValueError:
        return None

def _lfn_checksum(short11):
    s = 0
    for c in short11:
        s = (((s & 1) << 7) + (s >> 1) + c) & 0xFF
    return s

# Characters a short (8.3) name may begin with.
_SHORT_FIRST = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'()-@^_`{}~") \
    | set(range(0x80, 0x100))

def _lfn_belongs(lfn, short11, deleted):
    """Whether the long-name entries gathered before a short entry are its
    own. Each carries the checksum of the short name it was written for, so
    leftover entries from a deleted file are not pinned on whatever short
    entry now follows them."""
    sums = {c for _, _, c in lfn}
    if len(sums) != 1:
        return False
    want = sums.pop()
    if any((seq == 0xE5) != deleted for seq, _, _ in lfn):
        return False
    if not deleted:
        return _lfn_checksum(short11) == want
    # Deletion overwrote the short name's first byte. The checksum still
    # fixes it (each step is a bijection), so the long name belongs only if
    # the byte it implies is one a short name could begin with.
    rest = short11[1:]
    for first in _SHORT_FIRST:
        if _lfn_checksum(bytes([first]) + rest) == want:
            return True
    return False

class FatFS:
    name = "FAT"
    root_node = 0

    def __init__(self, source):
        self.source = source
        b = source.read_at(0, 512)
        if len(b) < 512:
            raise ValueError("Volume too small for a FAT boot sector.")
        self.bytes_per_sector = struct.unpack("<H", b[11:13])[0]
        self.sectors_per_cluster = b[13]
        self.reserved_sectors = struct.unpack("<H", b[14:16])[0]
        self.num_fats = b[16]
        self.root_entries = struct.unpack("<H", b[17:19])[0]
        total16 = struct.unpack("<H", b[19:21])[0]
        self.media = b[21]
        fat16_size = struct.unpack("<H", b[22:24])[0]
        total32 = struct.unpack("<I", b[32:36])[0]
        fat32_size = struct.unpack("<I", b[36:40])[0]

        if b[510:512] != b"\x55\xAA":
            raise ValueError("No boot signature; not a FAT volume.")
        if self.bytes_per_sector not in (512, 1024, 2048, 4096):
            raise ValueError("Implausible bytes-per-sector: %d"
                             % self.bytes_per_sector)
        if self.sectors_per_cluster not in (1, 2, 4, 8, 16, 32, 64, 128):
            raise ValueError("Implausible sectors-per-cluster: %d"
                             % self.sectors_per_cluster)
        if self.num_fats not in (1, 2):
            raise ValueError("Implausible FAT count: %d" % self.num_fats)
        if not self.reserved_sectors:
            raise ValueError("Zero reserved sectors.")
        if self.media != 0xF0 and self.media < 0xF8:
            raise ValueError("Implausible media descriptor: 0x%02X" % self.media)
        if not (fat16_size or fat32_size):
            raise ValueError("Zero-length FAT.")
        if not (total16 or total32):
            raise ValueError("Zero total sectors.")
        declared = (total16 or total32) * self.bytes_per_sector
        limit = getattr(source, "size", 0)
        if limit and declared > limit:
            raise ValueError(
                "Boot sector declares %d bytes but the volume is %d."
                % (declared, limit))

        self.fat_size = fat16_size or fat32_size
        self.total_sectors = total16 or total32
        self.cluster_size = self.bytes_per_sector * self.sectors_per_cluster

        self.root_dir_sectors = ((self.root_entries * 32)
                                 + self.bytes_per_sector - 1) // self.bytes_per_sector
        self.first_data_sector = (self.reserved_sectors
                                  + self.num_fats * self.fat_size
                                  + self.root_dir_sectors)
        data_sectors = self.total_sectors - self.first_data_sector
        self.cluster_count = data_sectors // self.sectors_per_cluster

        if self.cluster_count < 4085:
            self.bits, self.name = 12, "FAT12"
        elif self.cluster_count < 65525:
            self.bits, self.name = 16, "FAT16"
        else:
            self.bits, self.name = 32, "FAT32"

        self.root_cluster = struct.unpack("<I", b[44:48])[0] if self.bits == 32 else 0
        self.data_offset = self.first_data_sector * self.bytes_per_sector
        self.label = b[43:54].decode("latin-1").strip() if self.bits != 32 else \
            b[71:82].decode("latin-1").strip()
        self._fat = None

    def _load_fat(self):
        if self._fat is None:
            self._fat = self.source.read_at(
                self.reserved_sectors * self.bytes_per_sector,
                self.fat_size * self.bytes_per_sector)
        return self._fat

    def _fat_entry(self, n):
        fat = self._load_fat()
        if self.bits == 12:
            i = n + (n // 2)
            if i + 1 >= len(fat):
                return 0x0FFF
            v = fat[i] | (fat[i + 1] << 8)
            return (v >> 4) if (n & 1) else (v & 0x0FFF)
        if self.bits == 16:
            i = n * 2
            return struct.unpack("<H", fat[i:i + 2])[0] if i + 2 <= len(fat) else 0xFFFF
        i = n * 4
        return (struct.unpack("<I", fat[i:i + 4])[0] & 0x0FFFFFFF) \
            if i + 4 <= len(fat) else 0x0FFFFFFF

    def _eoc(self, v):
        return v >= {12: 0x0FF8, 16: 0xFFF8, 32: 0x0FFFFFF8}[self.bits]

    def cluster_offset(self, n):
        return ((self.first_data_sector + (n - 2) * self.sectors_per_cluster)
                * self.bytes_per_sector)

    def chain(self, start, max_clusters=1 << 22):
        out = []
        seen = set()
        c = start
        while 2 <= c < self.cluster_count + 2 and c not in seen and len(out) < max_clusters:
            seen.add(c)
            out.append(c)
            nxt = self._fat_entry(c)
            if self._eoc(nxt) or nxt < 2:
                break
            c = nxt
        return out

    def _contiguous(self, start, size):
        # A deleted file's chain is released, so its clusters are assumed to
        # follow the start cluster, as read_file() reads them.
        need = max(1, (size + self.cluster_size - 1) // self.cluster_size)
        end = min(start + need, self.cluster_count + 2)
        return list(range(start, end)) if 2 <= start < end else []

    def _clusters(self, entry):
        if entry.get("deleted"):
            return self._contiguous(entry["start_cluster"], entry["size"])
        return self.chain(entry["start_cluster"])

    def runs(self, start_cluster, size, clusters=None):
        if clusters is None:
            clusters = self.chain(start_cluster)
        if not clusters:
            return []
        runs, run_start, run_len = [], clusters[0], 1
        for prev, cur in zip(clusters, clusters[1:]):
            if cur == prev + 1:
                run_len += 1
            else:
                runs.append((run_start, run_len))
                run_start, run_len = cur, 1
        runs.append((run_start, run_len))
        out, remaining = [], size
        for c, n in runs:
            length = n * self.cluster_size
            take = min(length, remaining) if remaining is not None else length
            out.append({"offset": self.cluster_offset(c), "length": length,
                        "used": take, "cluster": c, "clusters": n})
            remaining -= take
            if remaining <= 0:
                break
        return out

    def _read_dir_bytes(self, cluster):
        if cluster == 0 and self.bits != 32:
            off = (self.reserved_sectors + self.num_fats * self.fat_size) \
                * self.bytes_per_sector
            return self.source.read_at(off, self.root_dir_sectors
                                       * self.bytes_per_sector), off
        clusters = self.chain(cluster or self.root_cluster)
        buf = bytearray()
        first_off = self.cluster_offset(clusters[0]) if clusters else 0
        for c in clusters:
            buf += self.source.read_at(self.cluster_offset(c), self.cluster_size)
        return bytes(buf), first_off

    def listdir(self, cluster=0, path="/"):
        data, base = self._read_dir_bytes(cluster)
        entries, lfn = [], []
        for i in range(0, len(data) - 31, 32):
            e = data[i:i + 32]
            if e[0] == 0x00:
                break
            attr = e[11]
            if attr == 0x0F:
                seq = e[0]
                part = (e[1:11] + e[14:26] + e[28:32]).decode("utf-16-le", "replace")
                part = part.split("\uffff")[0].split("\x00")[0]
                if lfn and (seq & 0x40 and seq != 0xE5
                            or lfn[-1][2] != e[13]
                            or (lfn[-1][0] == 0xE5) != (seq == 0xE5)):
                    # A new name begins here: the entries gathered so far
                    # belong to no short entry.
                    lfn = []
                lfn.append((seq, part, e[13]))
                continue
            deleted = e[0] == 0xE5
            short = e[0:8].decode("latin-1").rstrip()
            ext = e[8:11].decode("latin-1").rstrip()
            if deleted:
                short = "_" + short[1:]
            sname = short + ("." + ext if ext else "")
            long_name = ""
            if lfn and _lfn_belongs(lfn, e[0:11], deleted):
                if deleted:
                    # Deletion overwrites every sequence byte with 0xE5, so
                    # order comes from the layout instead: VFAT stores the
                    # parts last-first, immediately before the short entry.
                    parts = [p for _, p, _ in reversed(lfn)]
                else:
                    parts = [p for _, p, _ in sorted(
                        lfn, key=lambda x: x[0] & 0x3F)]
                long_name = "".join(parts)
            lfn = []
            if sname in (".", "..") or attr & 0x08:
                continue
            start = (struct.unpack("<H", e[26:28])[0]
                     | (struct.unpack("<H", e[20:22])[0] << 16))
            size = struct.unpack("<I", e[28:32])[0]
            is_dir = bool(attr & 0x10)
            name = long_name or sname
            entries.append({
                "name": name, "short_name": sname, "path": path.rstrip("/") + "/" + name,
                "is_dir": is_dir, "deleted": deleted, "size": 0 if is_dir else size,
                "start_cluster": start,
                "created": _dos_time(struct.unpack("<H", e[16:18])[0],
                                     struct.unpack("<H", e[14:16])[0], e[13]),
                "modified": _dos_time(struct.unpack("<H", e[24:26])[0],
                                      struct.unpack("<H", e[22:24])[0]),
                "accessed": _dos_time(struct.unpack("<H", e[18:20])[0], 0),
                "attributes": self._attrs(attr),
                "entry_offset": base + i,
                "id": "%d:%d" % (cluster, i),
            })
        return entries

    @staticmethod
    def _attrs(a):
        flags = [(0x01, "read-only"), (0x02, "hidden"), (0x04, "system"),
                 (0x10, "directory"), (0x20, "archive")]
        return [n for bit, n in flags if a & bit]

    def read_file(self, entry, max_bytes=None):
        size = entry["size"]
        if not entry["start_cluster"] or size == 0:
            return b""
        limit = size if max_bytes is None else min(size, max_bytes)
        out = bytearray()
        if entry.get("deleted"):
            need = (limit + self.cluster_size - 1) // self.cluster_size
            for k in range(need):
                out += self.source.read_at(
                    self.cluster_offset(entry["start_cluster"] + k),
                    self.cluster_size)
        else:
            for c in self.chain(entry["start_cluster"]):
                out += self.source.read_at(self.cluster_offset(c), self.cluster_size)
                if len(out) >= limit:
                    break
        return bytes(out[:limit])

    def read_range(self, entry, off, length):
        size = entry["size"]
        if not entry["start_cluster"] or not size:
            return b""
        length = min(length, max(0, size - off))
        if length <= 0:
            return b""
        if entry.get("deleted"):
            return self.source.read_at(
                self.cluster_offset(entry["start_cluster"]) + off, length)
        return read_runs(self.source,
                         self.runs(entry["start_cluster"], size), off, length)

    def slack(self, entry):
        if entry["is_dir"] or not entry["start_cluster"] or not entry["size"]:
            return None
        clusters = self._clusters(entry)
        if len(clusters) * self.cluster_size < entry["size"]:
            return None   # cut short: the file's end, and its slack, is unknown
        used_in_last = entry["size"] % self.cluster_size
        if used_in_last == 0:
            return None
        last = clusters[-1]
        off = self.cluster_offset(last) + used_in_last
        return {"offset": off, "length": self.cluster_size - used_in_last}

    def stat(self, entry):
        info = {"filesystem": self.name, "cluster_size": self.cluster_size}
        if entry["is_dir"] and entry.get("start_cluster"):
            info["record_offset"] = self.cluster_offset(entry["start_cluster"])
        if not entry["is_dir"] and entry["start_cluster"]:
            info["runs"] = self.runs(entry["start_cluster"], entry["size"],
                                     self._clusters(entry))
            info["slack"] = self.slack(entry)
            if entry.get("deleted"):
                info["recovery"] = ("FAT chain released. Content assumed "
                                    "contiguous from the start cluster; "
                                    "verify before relying on it.")
        return info

    def info(self):
        return {
            "type": self.name, "label": self.label,
            "bytes_per_sector": self.bytes_per_sector,
            "sectors_per_cluster": self.sectors_per_cluster,
            "cluster_size": self.cluster_size,
            "cluster_count": self.cluster_count,
            "fat_count": self.num_fats, "fat_size_sectors": self.fat_size,
            "first_data_offset": self.first_data_sector * self.bytes_per_sector,
            "root_cluster": self.root_cluster,
        }

    def allocated_extents(self):
        out = []
        stack = [(0, "/")]
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
                    for r in self.runs(e["start_cluster"], e["size"]):
                        out.append((r["offset"], r["offset"] + r["length"]))
        return out
