from .streams import UnsupportedStream
from .ranges import read_runs
from .. import decmpfs
from .. import xattr as xattr_mod
from ..text import t as _t
import datetime
import struct

SIG_HFSPLUS = b"H+"
SIG_HFSX = b"HX"
VOLUME_HEADER_OFFSET = 1024
CNID_ROOT_FOLDER = 2

REC_FOLDER = 0x0001
REC_FILE = 0x0002
REC_FOLDER_THREAD = 0x0003
REC_FILE_THREAD = 0x0004

ATTR_INLINE_DATA = 0x10
ATTR_FORK_DATA = 0x20
ATTR_EXTENTS = 0x30

KIND_LEAF = 0xFF

# Hard links: a file whose type/creator are hlnk/hfs+ (or a folder's fdrp/MACS)
# stands for an "indirect node" kept in a private folder at the volume root,
# named for the link's inode number. Compressed files carry UF_COMPRESSED.
PRIVATE_FILES = "\x00\x00\x00\x00HFS+ Private Data"
PRIVATE_DIRS = ".HFS+ Private Directory Data\r"
UF_COMPRESSED = 0x20
DECMPFS_XATTR = "com.apple.decmpfs"
_COMPRESSED_CACHE = 8

MAC_EPOCH = datetime.datetime(1904, 1, 1)

def mactime(v):
    if not v:
        return None
    try:
        return (MAC_EPOCH + datetime.timedelta(seconds=int(v))).isoformat() + "Z"
    except (OverflowError, ValueError):
        return None

class Fork:

    __slots__ = ("logical_size", "total_blocks", "extents")

    def __init__(self, data, off):
        self.logical_size = struct.unpack_from(">Q", data, off)[0]
        self.total_blocks = struct.unpack_from(">I", data, off + 12)[0]
        self.extents = []
        for i in range(8):
            start, count = struct.unpack_from(">II", data, off + 16 + i * 8)
            if count:
                self.extents.append((start, count))

class BTree:

    def __init__(self, fs, fork, name=""):
        self.fs = fs
        self.fork = fork
        self.name = name
        head = self.read(0, 512)
        if len(head) < 120:
            raise ValueError("%s b-tree header is truncated" % name)
        (self.depth, self.root, self.leaf_records, self.first_leaf,
         self.last_leaf, self.node_size, self.max_key_len,
         self.total_nodes, self.free_nodes) = struct.unpack_from(
            ">HIIIIHHII", head, 14)
        self.key_compare = head[14 + 30]
        self.attributes = struct.unpack_from(">I", head, 14 + 32)[0]
        if not self.node_size:
            raise ValueError("%s b-tree declares a zero node size" % name)

    def read(self, offset, length):
        out = bytearray()
        bs = self.fs.block_size
        remaining = length
        pos = offset
        for start, count in self.fork.extents:
            span = count * bs
            if pos >= span:
                pos -= span
                continue
            take = min(remaining, span - pos)
            out += self.fs.source.read_at(start * bs + pos, take)
            remaining -= take
            pos = 0
            if remaining <= 0:
                break
        return bytes(out)

    def node(self, index):
        return self.read(index * self.node_size, self.node_size)

    def records(self, node):
        if len(node) < 14:
            return []
        num = struct.unpack_from(">H", node, 10)[0]
        out = []
        for i in range(num):
            at = len(node) - 2 * (i + 1)
            if at < 14:
                break
            out.append(struct.unpack_from(">H", node, at)[0])
        return out

    def walk_leaves(self, limit=2_000_000):
        index = self.first_leaf
        seen = set()
        n = 0
        while index and index not in seen and n < limit:
            seen.add(index)
            node = self.node(index)
            if len(node) < 14:
                break
            kind = node[8]
            if kind != KIND_LEAF:
                break
            yield node
            n += 1
            index = struct.unpack_from(">I", node, 0)[0]

def _uni_name(data, off):
    if off + 2 > len(data):
        return "", off
    n = struct.unpack_from(">H", data, off)[0]
    raw = data[off + 2: off + 2 + n * 2]
    return raw.decode("utf-16-be", "replace").replace(":", "/"), off + 2 + n * 2

class HfsPlus:
    name = "HFS+"
    root_node = CNID_ROOT_FOLDER

    def __init__(self, source):
        self.source = source
        d = source.read_at(VOLUME_HEADER_OFFSET, 512)
        if len(d) < 512 or d[:2] not in (SIG_HFSPLUS, SIG_HFSX):
            raise ValueError("not an HFS+ volume")
        self.signature = d[:2]
        self.name = "HFSX" if self.signature == SIG_HFSX else "HFS+"
        self.version = struct.unpack_from(">H", d, 2)[0]
        self.attributes = struct.unpack_from(">I", d, 4)[0]
        self.created = mactime(struct.unpack_from(">I", d, 16)[0])
        self.modified = mactime(struct.unpack_from(">I", d, 20)[0])
        self.checked = mactime(struct.unpack_from(">I", d, 28)[0])
        (self.file_count, self.folder_count, self.block_size,
         self.total_blocks, self.free_blocks) = struct.unpack_from(">IIIII", d, 32)
        self.next_cnid = struct.unpack_from(">I", d, 64)[0]
        self.journal_block = struct.unpack_from(">I", d, 12)[0]

        self.allocation_fork = Fork(d, 112)
        self.extents_fork = Fork(d, 192)
        self.catalog_fork = Fork(d, 272)
        self.attributes_fork = Fork(d, 352)

        self.findings = []
        if not self.attributes & (1 << 8):
            self.findings.append(
                "Volume was not unmounted cleanly; the journal may hold "
                "changes not reflected in the catalog.")
        if self.signature == SIG_HFSX:
            self.findings.append(
                "HFSX volume — filename comparison may be case-sensitive.")

        self.catalog = BTree(self, self.catalog_fork, "catalog")
        try:
            self.extents = BTree(self, self.extents_fork, "extents overflow")
        except ValueError:
            self.extents = None
        try:
            self.attrs = BTree(self, self.attributes_fork, "attributes")
        except ValueError:
            self.attrs = None
        self._by_parent = None
        self._threads = None
        self._xattrs = None

    def _index(self):
        if self._by_parent is not None:
            return self._by_parent, self._threads
        by_parent = {}
        threads = {}
        for node in self.catalog.walk_leaves():
            for off in self.catalog.records(node):
                if off + 8 > len(node):
                    continue
                key_len = struct.unpack_from(">H", node, off)[0]
                parent = struct.unpack_from(">I", node, off + 2)[0]
                name, after = _uni_name(node, off + 6)
                data_off = off + 2 + key_len
                data_off += data_off & 1
                if data_off + 2 > len(node):
                    continue
                rtype = struct.unpack_from(">H", node, data_off)[0]

                if rtype in (REC_FOLDER_THREAD, REC_FILE_THREAD):
                    tparent = struct.unpack_from(">I", node, data_off + 4)[0]
                    tname, _ = _uni_name(node, data_off + 8)
                    threads[parent] = (tparent, tname)
                    continue
                if rtype == REC_FOLDER:
                    rec = self._folder(node, data_off, name, parent)
                elif rtype == REC_FILE:
                    rec = self._file(node, data_off, name, parent)
                else:
                    continue
                by_parent.setdefault(parent, []).append(rec)
        self._by_parent, self._threads = by_parent, threads
        self._resolve_links(by_parent)
        self._resolve_compression(by_parent)
        return by_parent, threads

    def _private_children(self, by_parent, name, prefix):
        """{number: record} of the entries in the private folder `name`
        (at the volume root) whose names are `prefix` and a number."""
        out = {}
        for folder in by_parent.get(CNID_ROOT_FOLDER, []):
            if not folder["is_dir"] or folder["name"] != name:
                continue
            for rec in by_parent.get(folder["cnid"], []):
                tail = rec["name"][len(prefix):]
                if rec["name"].startswith(prefix) and tail.isdigit():
                    out[int(tail)] = rec
        return out

    def _resolve_links(self, by_parent):
        """Give each hard link the content of the file it stands for. The
        link keeps its own name, place and catalog ID; size, forks and
        extended attributes come from the indirect node, and so do the
        modified and accessed times (the node is what is written to)."""
        inodes = links = dir_links = None
        lost = 0
        for recs in by_parent.values():
            for rec in recs:
                if rec["is_dir"] or "_ftype" not in rec:
                    continue
                kind = (rec["_ftype"], rec["_creator"])
                if kind == (b"hlnk", b"hfs+"):
                    if inodes is None:
                        inodes = self._private_children(
                            by_parent, PRIVATE_FILES, "iNode")
                    node = inodes.get(rec["_special"])
                    rec["hard_link"] = True
                    rec["link_inode"] = rec["_special"]
                    if node is None:
                        rec["hard_link_unresolved"] = True
                        lost += 1
                        continue
                    rec["link_count"] = node["_special"]
                    rec["hard_link_target"] = "%s/%s" % (
                        PRIVATE_FILES.replace("\x00", "\u2400"), node["name"])
                    rec["_content_cnid"] = node["cnid"]
                    for key in ("size", "resource_size", "_data_extents",
                                "_data_blocks", "_rsrc_extents",
                                "_rsrc_blocks", "_owner_flags", "modified",
                                "accessed", "attr_modified"):
                        rec[key] = node[key]
                elif kind == (b"fdrp", b"MACS"):
                    if dir_links is None:
                        dir_links = self._private_children(
                            by_parent, PRIVATE_DIRS, "dir_")
                    node = dir_links.get(rec["_special"])
                    rec["hard_link"] = True
                    rec["hard_link_dir"] = True
                    rec["link_inode"] = rec["_special"]
                    if node is None or not node["is_dir"]:
                        rec["hard_link_unresolved"] = True
                        lost += 1
                        continue
                    rec["hard_link_target"] = "%s/%s" % (PRIVATE_DIRS.strip(), node["name"])
                    rec["link_target_cnid"] = node["cnid"]
        if lost:
            self.findings.append(_t("hfsplus.links_unresolved") % lost)

    def _resolve_compression(self, by_parent):
        """Note the files that carry UF_COMPRESSED, and take the size of a
        file Strata can decompress from its decmpfs header."""
        unsupported = damaged = 0
        for recs in by_parent.values():
            for rec in recs:
                if rec["is_dir"] or not rec.get("_owner_flags", 0) & UF_COMPRESSED:
                    continue
                cnid = rec.get("_content_cnid", rec["cnid"])
                value = None
                for x in self._xattrs_index().get(cnid, ()):
                    if x["name"] == DECMPFS_XATTR:
                        value = x.get("value")
                        break
                header = decmpfs.parse_header(value)
                if header is None:
                    damaged += 1
                    rec["compression_damaged"] = True
                    continue
                rec["compression"] = decmpfs.describe(header)
                rec["uncompressed_size"] = header["size"]
                if header["supported"]:
                    rec["_decmpfs"] = header
                    rec["size"] = header["size"]
                else:
                    unsupported += 1
                    rec["compression_unsupported"] = True
        if unsupported:
            self.findings.append(_t("hfsplus.compression_unsupported") % unsupported)
        if damaged:
            self.findings.append(_t("hfsplus.compression_damaged") % damaged)

    @staticmethod
    def _attr_record(node, key_off, data_off):
        """(file_id, {"name", "size", "value"?}) for one attributes B-tree
        leaf record, or None if the key or record header does not fit in
        the node. Only kHFSPlusAttrInlineData (0x10) carries its value
        here -- the value lives inside the record; a fork-based attribute
        (0x20, used once an attribute is too large to stay inline) points
        at allocation blocks this does not walk, so only its name and
        size are reported."""
        if key_off + 14 > len(node):
            return None
        file_id = struct.unpack_from(">I", node, key_off + 4)[0]
        name_len = struct.unpack_from(">H", node, key_off + 12)[0]
        raw_name = node[key_off + 14:key_off + 14 + name_len * 2]
        name = raw_name.decode("utf-16-be", "replace")
        if data_off + 4 > len(node):
            return file_id, {"name": name, "size": None}
        rtype = struct.unpack_from(">I", node, data_off)[0]
        # HFSPlusAttrData: type, two reserved words, size, then the value.
        if rtype == ATTR_INLINE_DATA and data_off + 16 <= len(node):
            size = struct.unpack_from(">I", node, data_off + 12)[0]
            value = node[data_off + 16:data_off + 16 + size]
            if len(value) == size:
                return file_id, {"name": name, "size": size, "value": value}
            return file_id, {"name": name, "size": size}
        return file_id, {"name": name, "size": None}

    def _xattrs_index(self):
        if self._xattrs is not None:
            return self._xattrs
        by_cnid = {}
        if self.attrs:
            for node in self.attrs.walk_leaves():
                for off in self.attrs.records(node):
                    if off + 2 > len(node):
                        continue
                    key_len = struct.unpack_from(">H", node, off)[0]
                    data_off = off + 2 + key_len
                    data_off += data_off & 1
                    if data_off > len(node):
                        continue
                    got = self._attr_record(node, off, data_off)
                    if got is None:
                        continue
                    file_id, rec = got
                    by_cnid.setdefault(file_id, []).append(rec)
        self._xattrs = by_cnid
        return by_cnid

    def _folder(self, node, off, name, parent):
        (valence, cnid, created, modified, attr_mod, accessed,
         backup) = struct.unpack_from(">IIIIIII", node, off + 4)
        return {
            "name": name, "is_dir": True, "cnid": cnid, "parent": parent,
            "size": 0, "valence": valence,
            "created": mactime(created), "modified": mactime(modified),
            "accessed": mactime(accessed), "attr_modified": mactime(attr_mod),
            "deleted": False,
        }

    def _file(self, node, off, name, parent):
        flags = struct.unpack_from(">H", node, off + 2)[0]
        cnid = struct.unpack_from(">I", node, off + 8)[0]
        (created, modified, attr_mod, accessed,
         backup) = struct.unpack_from(">IIIII", node, off + 12)
        owner_flags = node[off + 41]
        special = struct.unpack_from(">I", node, off + 44)[0]
        ftype, creator = bytes(node[off + 48:off + 52]), bytes(node[off + 52:off + 56])
        data_fork = Fork(node, off + 88)
        rsrc_fork = Fork(node, off + 168)
        return {
            "_owner_flags": owner_flags, "_special": special,
            "_ftype": ftype, "_creator": creator,
            "_rsrc_blocks": rsrc_fork.total_blocks,
            "name": name, "is_dir": False, "cnid": cnid, "parent": parent,
            "size": data_fork.logical_size,
            "resource_size": rsrc_fork.logical_size,
            "created": mactime(created), "modified": mactime(modified),
            "accessed": mactime(accessed), "attr_modified": mactime(attr_mod),
            "locked": bool(flags & 0x01),
            "deleted": False,
            "_data_extents": data_fork.extents,
            "_data_blocks": data_fork.total_blocks,
            "_rsrc_extents": rsrc_fork.extents,
        }

    def listdir(self, cnid=CNID_ROOT_FOLDER, path="/"):
        by_parent, _threads = self._index()
        out = []
        for rec in by_parent.get(int(cnid), []):
            e = dict(rec)
            e["path"] = (path.rstrip("/") + "/" + e["name"]) if path else e["name"]
            out.append(e)
        out.sort(key=lambda e: (not e["is_dir"], (e["name"] or "").lower()))
        return out

    def _all_extents(self, entry, fork="data"):
        rsrc = fork != "data"
        extents = list(entry.get("_rsrc_extents" if rsrc else "_data_extents")
                       or [])
        total = sum(c for _s, c in extents)
        want = entry.get("_rsrc_blocks" if rsrc else "_data_blocks") or 0
        if total >= want or not self.extents:
            return extents
        cnid = entry.get("_content_cnid", entry.get("cnid"))
        wanted_type = 0xFF if rsrc else 0x00
        for node in self.extents.walk_leaves():
            for off in self.extents.records(node):
                if off + 12 > len(node):
                    continue
                key_len = struct.unpack_from(">H", node, off)[0]
                fork_type = node[off + 2]
                rec_cnid = struct.unpack_from(">I", node, off + 4)[0]
                if rec_cnid != cnid or fork_type != wanted_type:
                    continue
                data_off = off + 2 + key_len
                data_off += data_off & 1
                for i in range(8):
                    if data_off + 8 * (i + 1) > len(node):
                        break
                    s, c = struct.unpack_from(">II", node, data_off + i * 8)
                    if c:
                        extents.append((s, c))
        return extents

    def _decompressed(self, entry):
        """The decmpfs reader for a compressed file, or None if it is not
        one Strata can decompress. Raises DecmpfsError for a file whose
        compressed data cannot be laid out."""
        header = entry.get("_decmpfs")
        if header is None:
            return None
        key = entry.get("cnid")
        cache = self.__dict__.setdefault("_compressed", {})
        got = cache.get(key)
        if got is None:
            rsize = entry.get("resource_size") or 0
            got = decmpfs.Compressed(
                header, lambda off, n: self.read_range(entry, off, n, "rsrc"),
                rsize)
            if len(cache) >= _COMPRESSED_CACHE:
                cache.clear()
            cache[key] = got
        return got

    def read_file(self, entry, max_bytes=None, stream=""):
        if not stream and "_decmpfs" in entry:
            comp = self._decompressed(entry)
            want = comp.size if max_bytes is None else min(comp.size, max_bytes)
            return comp.read_at(0, want)
        want = entry.get("size") or 0
        if stream in ("rsrc", "resource"):
            want = entry.get("resource_size") or 0
            extents = self._all_extents(entry, "rsrc")
        elif stream:
            raise UnsupportedStream("HFS+", stream)
        else:
            extents = self._all_extents(entry, "data")
        if max_bytes is not None:
            want = min(want, max_bytes)
        out = bytearray()
        bs = self.block_size
        for start, count in extents:
            if len(out) >= want:
                break
            take = min(want - len(out), count * bs)
            out += self.source.read_at(start * bs, take)
        return bytes(out[:want])

    def read_range(self, entry, off, length, stream=""):
        if not stream and "_decmpfs" in entry:
            return self._decompressed(entry).read_at(off, length)
        if stream in ("rsrc", "resource"):
            want = entry.get("resource_size") or 0
            extents = self._all_extents(entry, "rsrc")
        elif stream:
            raise UnsupportedStream("HFS+", stream)
        else:
            want = entry.get("size") or 0
            extents = self._all_extents(entry, "data")
        bs = self.block_size
        runs = [{"offset": s * bs, "length": c * bs} for s, c in extents]
        return read_runs(self.source, runs, off,
                         min(length, max(0, want - off)))

    def stat(self, entry):
        info = {"filesystem": self.name, "cluster_size": self.block_size,
                "cnid": entry.get("cnid"), "parent": entry.get("parent")}
        extents = self._all_extents(entry, "data")
        if extents and not entry.get("is_dir"):
            runs = []
            remaining = entry.get("size") or 0
            for start, count in extents:
                length = min(remaining, count * self.block_size)
                runs.append({"offset": start * self.block_size,
                             "length": count * self.block_size,
                             "used": length, "sparse": False})
                remaining -= length
                if remaining <= 0:
                    break
            info["runs"] = runs
            tail = (entry.get("size") or 0) % self.block_size
            if tail and runs:
                last = runs[-1]
                info["slack"] = {
                    "offset": last["offset"] + tail,
                    "length": self.block_size - tail,
                }
        if entry.get("resource_size"):
            info["note"] = ("This file has a resource fork of %d bytes, which "
                            "is separate from its data and is not shown in the "
                            "size column."
                            % entry["resource_size"])
        if entry.get("is_dir"):
            info["record_offset"] = None
        notes = [info["note"]] if info.get("note") else []
        if entry.get("hard_link"):
            info["hard_link"] = {
                k: entry[k] for k in ("link_inode", "link_count",
                                      "hard_link_target", "link_target_cnid",
                                      "hard_link_unresolved") if k in entry}
            notes.append(self._link_note(entry))
        if entry.get("compression"):
            info["compression"] = {"codec": entry["compression"],
                                   "uncompressed_size": entry["uncompressed_size"]}
            notes.append(self._compression_note(entry, info))
        elif entry.get("compression_damaged"):
            notes.append(_t("hfsplus.compressed_no_header"))
        if notes:
            info["note"] = " ".join(notes)
        xattrs = self._xattrs_index().get(
            entry.get("_content_cnid", entry.get("cnid")))
        if xattrs:
            info["xattrs"] = xattr_mod.for_client(xattrs)
        return info

    @staticmethod
    def _link_note(entry):
        if entry.get("hard_link_unresolved"):
            return _t("hfsplus.link_lost") % entry["link_inode"]
        if entry.get("hard_link_dir"):
            return _t("hfsplus.dir_link") % entry["hard_link_target"]
        return _t("hfsplus.file_link") % (
            entry["hard_link_target"], entry.get("link_count", 0))

    def _compression_note(self, entry, info):
        if entry.get("compression_unsupported"):
            return _t("hfsplus.compressed_unread") % entry["compression"]
        try:
            comp = self._decompressed(entry)
            comp.read_at(0, 1)
        except decmpfs.DecmpfsError as exc:
            return _t("hfsplus.compressed_failed") % (entry["compression"], exc)
        text = _t("hfsplus.compressed") % entry["compression"]
        if comp.findings:
            info["compression"]["findings"] = list(comp.findings)
            text += " " + " ".join(comp.findings)
        return text

    def label(self):
        try:
            _by_parent, threads = self._index()
        except Exception:
            return None
        got = threads.get(CNID_ROOT_FOLDER)
        return got[1] if got else None

    def info(self):
        return {
            "type": self.name, "label": self.label(),
            "version": self.version,
            "cluster_size": self.block_size,
            "total_blocks": self.total_blocks,
            "free_blocks": self.free_blocks,
            "files": self.file_count,
            "folders": self.folder_count,
            "created": self.created,
            "modified": self.modified,
            "journaled": bool(self.attributes & (1 << 13)),
            "next_cnid": self.next_cnid,
            "findings": self.findings,
        }

def detect(source):
    try:
        d = source.read_at(VOLUME_HEADER_OFFSET, 2)
    except Exception:
        return None
    if d == SIG_HFSPLUS:
        return "HFS+"
    if d == SIG_HFSX:
        return "HFSX"
    return None

def open_volume(source):
    return HfsPlus(source)
