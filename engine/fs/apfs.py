from .streams import UnsupportedStream
from .ranges import read_runs
from .. import xattr as xattr_mod
import datetime
import struct

NX_MAGIC = b"NXSB"
APFS_MAGIC = b"APSB"

OBJECT_TYPE_MASK = 0x0000FFFF
OBJ_BTREE_NODE = 0x0003

BTNODE_ROOT = 0x0001
BTNODE_LEAF = 0x0002
BTNODE_FIXED_KV_SIZE = 0x0004
TYPE_INODE = 3
TYPE_XATTR = 4
TYPE_DSTREAM_ID = 6
TYPE_FILE_EXTENT = 8
TYPE_DIR_REC = 9

ROOT_DIR_OID = 2

def fletcher64(data):
    body = data[8:]
    if len(body) % 4:
        body = body + b"\x00" * (4 - len(body) % 4)
    s1 = s2 = 0
    m = 0xFFFFFFFF
    for i in range(0, len(body), 4):
        w = struct.unpack("<I", body[i:i + 4])[0]
        s1 = (s1 + w) % m
        s2 = (s2 + s1) % m
    c1 = m - ((s1 + s2) % m)
    c2 = m - ((s1 + c1) % m)
    return (c2 << 32) | c1

def apfs_time(ns):
    if not ns:
        return None
    try:
        return (datetime.datetime(1970, 1, 1)
                + datetime.timedelta(microseconds=ns // 1000)).isoformat() + "Z"
    except (OverflowError, ValueError):
        return None

def looks_like_apfs(source):
    d = source.read_at(0, 64)
    return len(d) >= 36 and d[32:36] == NX_MAGIC

class ObjHeader:
    __slots__ = ("cksum", "oid", "xid", "type", "subtype", "valid")

    def __init__(self, buf):
        if len(buf) < 32:
            self.valid = False
            self.cksum = self.oid = self.xid = self.type = self.subtype = 0
            return
        self.cksum = struct.unpack("<Q", buf[0:8])[0]
        self.oid, self.xid = struct.unpack("<QQ", buf[8:24])
        self.type, self.subtype = struct.unpack("<II", buf[24:32])
        self.valid = True

    @property
    def kind(self):
        return self.type & OBJECT_TYPE_MASK

class BTreeNode:

    def __init__(self, buf, block_size):
        self.buf = buf
        self.hdr = ObjHeader(buf)
        self.flags, self.level = struct.unpack("<HH", buf[32:36])
        self.nkeys = struct.unpack("<I", buf[36:40])[0]
        toc_off, toc_len = struct.unpack("<HH", buf[40:44])
        self.data_start = 56
        self.toc_start = self.data_start + toc_off
        self.toc_len = toc_len
        self.key_start = self.toc_start + toc_len
        self.val_end = len(buf) - (40 if self.flags & BTNODE_ROOT else 0)
        self.fixed = bool(self.flags & BTNODE_FIXED_KV_SIZE)
        self.leaf = bool(self.flags & BTNODE_LEAF)

    def items(self):
        for i in range(self.nkeys):
            if self.fixed:
                at = self.toc_start + i * 4
                if at + 4 > len(self.buf):
                    return
                koff, voff = struct.unpack("<HH", self.buf[at:at + 4])
                klen = None
                vlen = None
            else:
                at = self.toc_start + i * 8
                if at + 8 > len(self.buf):
                    return
                koff, klen, voff, vlen = struct.unpack("<HHHH",
                                                       self.buf[at:at + 8])
            ks = self.key_start + koff
            if klen is None:
                klen = self._fixed_key_len(i)
            key = self.buf[ks:ks + klen]
            ve = self.val_end - voff
            if vlen is None:
                vlen = self._fixed_val_len(i)
            val = self.buf[ve:ve + vlen] if vlen else self.buf[ve:ve + 8]
            yield key, val

    def _fixed_key_len(self, i):
        if self.nkeys < 2:
            return 16
        a = struct.unpack("<H", self.buf[self.toc_start:self.toc_start + 2])[0]
        b = struct.unpack("<H", self.buf[self.toc_start + 4:
                                         self.toc_start + 6])[0]
        return abs(b - a) or 16

    def _fixed_val_len(self, i):
        if self.nkeys < 2:
            return 16
        a = struct.unpack("<H", self.buf[self.toc_start + 2:
                                         self.toc_start + 4])[0]
        b = struct.unpack("<H", self.buf[self.toc_start + 6:
                                         self.toc_start + 8])[0]
        return abs(a - b) or 16

class ApfsContainer:
    def __init__(self, source):
        self.source = source
        self.findings = []
        buf = source.read_at(0, 4096)
        if len(buf) < 36 or buf[32:36] != NX_MAGIC:
            raise ValueError("No APFS container superblock (NXSB) at block 0.")
        self.block_size = struct.unpack("<I", buf[36:40])[0]
        if self.block_size not in (4096, 8192, 16384, 32768, 65536):
            raise ValueError("Implausible APFS block size %d" % self.block_size)
        self.nx = self._parse_nx(source.read_at(0, self.block_size))
        latest = self._latest_checkpoint()
        if latest and latest["xid"] > self.nx["xid"]:
            self.findings.append(
                "Block 0 superblock is stale (xid %d); using checkpoint at "
                "block %d (xid %d)." % (self.nx["xid"], latest["block"],
                                        latest["xid"]))
            self.nx = latest
        self.omap = self._load_omap(self.nx["omap_oid"])

    def _parse_nx(self, buf):
        h = ObjHeader(buf)
        d = {
            "xid": h.xid, "oid": h.oid,
            "block_size": struct.unpack("<I", buf[36:40])[0],
            "block_count": struct.unpack("<Q", buf[40:48])[0],
            "incompat": struct.unpack("<Q", buf[64:72])[0],
            "uuid": buf[72:88].hex(),
            "next_oid": struct.unpack("<Q", buf[88:96])[0],
            "next_xid": struct.unpack("<Q", buf[96:104])[0],
            "xp_desc_blocks": struct.unpack("<I", buf[104:108])[0] & 0x7FFFFFFF,
            "xp_desc_base": struct.unpack("<Q", buf[112:120])[0],
            "xp_desc_index": struct.unpack("<I", buf[136:140])[0],
            "xp_desc_len": struct.unpack("<I", buf[140:144])[0],
            "spaceman_oid": struct.unpack("<Q", buf[152:160])[0],
            "omap_oid": struct.unpack("<Q", buf[160:168])[0],
            "reaper_oid": struct.unpack("<Q", buf[168:176])[0],
            "max_file_systems": struct.unpack("<I", buf[180:184])[0],
            "block": 0,
        }
        fs_oids = []
        for i in range(min(100, d["max_file_systems"] or 100)):
            at = 184 + i * 8
            if at + 8 > len(buf):
                break
            oid = struct.unpack("<Q", buf[at:at + 8])[0]
            if oid:
                fs_oids.append(oid)
        d["fs_oids"] = fs_oids
        if not self._checksum_ok(buf):
            self.findings.append("Container superblock failed its Fletcher-64 "
                                 "checksum.")
        return d

    def _checksum_ok(self, buf):
        stored = struct.unpack("<Q", buf[0:8])[0]
        return stored == fletcher64(buf)

    def _latest_checkpoint(self):
        base = self.nx["xp_desc_base"]
        count = min(self.nx["xp_desc_blocks"], 2048)
        best = None
        for i in range(count):
            blk = base + i
            buf = self.source.read_at(blk * self.block_size, self.block_size)
            if len(buf) < 40 or buf[32:36] != NX_MAGIC:
                continue
            if not self._checksum_ok(buf):
                continue
            d = self._parse_nx(buf)
            d["block"] = blk
            if best is None or d["xid"] > best["xid"]:
                best = d
        return best

    def read_block(self, blk, verify=True, label=""):
        buf = self.source.read_at(blk * self.block_size, self.block_size)
        if verify and len(buf) >= 32:
            stored = struct.unpack("<Q", buf[0:8])[0]
            if stored and stored != fletcher64(buf):
                self.findings.append(
                    "Checksum mismatch on block %d%s." % (blk, " (" + label + ")"
                                                          if label else ""))
        return buf

    def _load_omap(self, omap_oid):
        if not omap_oid:
            return {}
        buf = self.read_block(omap_oid, label="omap")
        if len(buf) < 56:
            return {}
        tree_oid = struct.unpack("<Q", buf[48:56])[0]
        mapping = {}
        self._walk_omap(tree_oid, mapping, seen=set())
        return mapping

    def _walk_omap(self, node_block, mapping, depth=0, seen=None):
        if seen is None:
            seen = set()
        if depth > 16 or not node_block or node_block in seen:
            return
        seen.add(node_block)
        buf = self.read_block(node_block, label="omap node")
        if len(buf) < 56 or ObjHeader(buf).kind != OBJ_BTREE_NODE and depth:
            pass
        node = BTreeNode(buf, self.block_size)
        for key, val in node.items():
            if len(key) < 16:
                continue
            oid, xid = struct.unpack("<QQ", key[0:16])
            if node.leaf:
                if len(val) < 16:
                    continue
                flags, size = struct.unpack("<II", val[0:8])
                paddr = struct.unpack("<Q", val[8:16])[0]
                prev = mapping.get(oid)
                if prev is None or xid >= prev[1]:
                    mapping[oid] = (paddr, xid, size, flags)
            else:
                if len(val) >= 8:
                    child = struct.unpack("<Q", val[0:8])[0]
                    self._walk_omap(child, mapping, depth + 1, seen)

    def resolve(self, oid):
        hit = self.omap.get(oid)
        return hit[0] if hit else None

    def volumes(self):
        out = []
        for oid in self.nx["fs_oids"]:
            blk = self.resolve(oid)
            if blk is None:
                self.findings.append("Volume object %d is not in the container "
                                     "object map." % oid)
                continue
            buf = self.read_block(blk, label="volume superblock")
            if len(buf) < 36 or buf[32:36] != APFS_MAGIC:
                self.findings.append("Object %d at block %d is not an APSB."
                                     % (oid, blk))
                continue
            out.append(ApfsVolume(self, buf, blk, oid))
        return out

    def default_volume(self):
        vols = self.volumes()
        if not vols:
            raise ValueError("APFS container holds no readable volumes.")
        return vols[0]

    def info(self):
        return {
            "type": "APFS container", "uuid": self.nx["uuid"],
            "block_size": self.block_size,
            "blocks": self.nx["block_count"],
            "transaction": self.nx["xid"],
            "superblock_block": self.nx["block"],
            "volumes": len(self.nx["fs_oids"]),
            "objects_mapped": len(self.omap),
            "findings": list(self.findings),
        }

class ApfsVolume:
    name = "APFS"
    root_node = 2

    def __init__(self, container, buf, block, oid):
        self.c = container
        self.source = container.source
        self.block_size = container.block_size
        self.cluster_size = self.block_size
        self.data_offset = 0
        self.block = block
        self.oid = oid
        self.findings = []
        h = ObjHeader(buf)
        self.xid = h.xid
        self.fs_index = struct.unpack("<I", buf[36:40])[0]
        self.features = struct.unpack("<Q", buf[40:48])[0]
        self.incompat = struct.unpack("<Q", buf[56:64])[0]
        self.unmount_time = apfs_time(struct.unpack("<Q", buf[64:72])[0])
        self.reserve_blocks = struct.unpack("<Q", buf[72:80])[0]
        self.alloc_count = struct.unpack("<Q", buf[88:96])[0]
        self.root_tree_type = struct.unpack("<I", buf[116:120])[0]
        self.omap_oid = struct.unpack("<Q", buf[128:136])[0]
        self.root_tree_oid = struct.unpack("<Q", buf[136:144])[0]
        self.extentref_oid = struct.unpack("<Q", buf[144:152])[0]
        self.snap_meta_oid = struct.unpack("<Q", buf[152:160])[0]
        self.next_obj_id = struct.unpack("<Q", buf[184:192])[0] \
            if len(buf) >= 192 else 0
        self.num_files = struct.unpack("<Q", buf[192:200])[0] \
            if len(buf) >= 200 else 0
        self.num_dirs = struct.unpack("<Q", buf[200:208])[0] \
            if len(buf) >= 208 else 0
        self.uuid = buf[240:256].hex() if len(buf) >= 256 else ""
        self.label = ""
        if len(buf) >= 960:
            self.label = buf[704:960].split(b"\x00")[0].decode("utf-8", "replace")
        self.encrypted = bool(self.incompat & 0x2) or bool(self.features & 0x4)

        self.omap = {}
        if self.omap_oid:
            omap_block = container.resolve(self.omap_oid) or self.omap_oid
            buf2 = container.read_block(omap_block, label="volume omap")
            if len(buf2) >= 56:
                tree = struct.unpack("<Q", buf2[48:56])[0]
                container._walk_omap(tree, self.omap)
        self._records = None

    def resolve(self, oid):
        hit = self.omap.get(oid)
        return hit[0] if hit else None

    def _catalog(self):
        if self._records is not None:
            return self._records
        recs = {"inode": {}, "drec": {}, "extent": {}, "dstream": {},
                "xattr": {}}
        root_block = self.resolve(self.root_tree_oid)
        if root_block is None:
            self.findings.append("Catalog root %d is not in the volume object "
                                 "map." % self.root_tree_oid)
            self._records = recs
            return recs
        self._walk_catalog(root_block, recs, seen=set())
        self._records = recs
        return recs

    def _walk_catalog(self, block, recs, depth=0, seen=None):
        if seen is None:
            seen = set()
        if depth > 24 or block in seen:
            return
        seen.add(block)
        buf = self.c.read_block(block, label="catalog node")
        if len(buf) < 56:
            return
        node = BTreeNode(buf, self.block_size)
        for key, val in node.items():
            if len(key) < 8:
                continue
            packed = struct.unpack("<Q", key[0:8])[0]
            oid = packed & 0x0FFFFFFFFFFFFFFF
            rtype = (packed >> 60) & 0x0F
            if not node.leaf:
                if len(val) >= 8:
                    child_oid = struct.unpack("<Q", val[0:8])[0]
                    child = self.resolve(child_oid)
                    if child is None:
                        child = child_oid
                    self._walk_catalog(child, recs, depth + 1, seen)
                continue
            if rtype == TYPE_INODE:
                recs["inode"][oid] = self._parse_inode(oid, val)
            elif rtype == TYPE_DIR_REC:
                recs["drec"].setdefault(oid, []).append(
                    self._parse_drec(key, val))
            elif rtype == TYPE_FILE_EXTENT:
                if len(key) >= 16 and len(val) >= 24:
                    logical = struct.unpack("<Q", key[8:16])[0]
                    len_flags = struct.unpack("<Q", val[0:8])[0]
                    phys = struct.unpack("<Q", val[8:16])[0]
                    recs["extent"].setdefault(oid, []).append({
                        "logical": logical,
                        "length": len_flags & 0x00FFFFFFFFFFFFFF,
                        "crypto": len_flags >> 56,
                        "phys": phys,
                    })
            elif rtype == TYPE_DSTREAM_ID:
                recs["dstream"][oid] = val
            elif rtype == TYPE_XATTR:
                recs["xattr"].setdefault(oid, []).append(self._parse_xattr(key,
                                                                          val))

    @staticmethod
    def _parse_xfields(blob):
        out = {}
        if len(blob) < 4:
            return out
        num, used = struct.unpack("<HH", blob[0:4])
        if num > 64:
            return out
        head = 4
        data_at = 4 + num * 4
        for i in range(num):
            at = head + i * 4
            if at + 4 > len(blob):
                break
            xtype, xflags, xsize = struct.unpack("<BBH", blob[at:at + 4])
            field = blob[data_at:data_at + xsize]
            if xtype == 8 and len(field) >= 8:
                out["size"] = struct.unpack("<Q", field[0:8])[0]
                if len(field) >= 16:
                    out["alloced_size"] = struct.unpack("<Q", field[8:16])[0]
            elif xtype == 4:
                out["name"] = field.split(b"\x00")[0].decode("utf-8", "replace")
            elif xtype == 14 and len(field) >= 8:
                out["sparse_bytes"] = struct.unpack("<Q", field[0:8])[0]
            data_at += xsize + (-xsize % 8)
        return out

    @classmethod
    def _parse_inode(cls, oid, v):
        if len(v) < 92:
            return {"oid": oid}
        parent, private = struct.unpack("<QQ", v[0:16])
        create, mod, change, access = struct.unpack("<QQQQ", v[16:48])
        flags = struct.unpack("<Q", v[48:56])[0]
        nchildren = struct.unpack("<i", v[56:60])[0]
        bsd_flags = struct.unpack("<I", v[68:72])[0]
        owner, group = struct.unpack("<II", v[72:80])
        mode = struct.unpack("<H", v[80:82])[0]
        xf = cls._parse_xfields(v[92:])
        return {
            "oid": oid, "parent": parent, "private_id": private,
            "size": xf.get("size"), "alloced_size": xf.get("alloced_size"),
            "xname": xf.get("name"),
            "created": apfs_time(create), "modified": apfs_time(mod),
            "changed": apfs_time(change), "accessed": apfs_time(access),
            "flags": flags, "nchildren": nchildren, "mode": mode,
            "uid": owner, "gid": group, "bsd_flags": bsd_flags,
            "is_dir": (mode & 0xF000) == 0x4000,
        }

    @staticmethod
    def _parse_drec(key, val):
        name = ""
        if len(key) >= 12:
            packed = struct.unpack("<I", key[8:12])[0]
            nlen = packed & 0x3FF
            name = key[12:12 + nlen].split(b"\x00")[0].decode("utf-8", "replace")
        file_id = struct.unpack("<Q", val[0:8])[0] if len(val) >= 8 else 0
        added = apfs_time(struct.unpack("<Q", val[8:16])[0]) \
            if len(val) >= 16 else None
        flags = struct.unpack("<H", val[16:18])[0] if len(val) >= 18 else 0
        return {"name": name, "file_id": file_id, "added": added,
                "kind": flags & 0x0F}

    # Extended-attribute value flags (j_xattr_val_t).
    XATTR_DATA_STREAM = 0x0001
    XATTR_DATA_EMBEDDED = 0x0002

    @staticmethod
    def _parse_xattr(key, val):
        name = ""
        if len(key) >= 10:
            nlen = struct.unpack("<H", key[8:10])[0]
            name = key[10:10 + nlen].split(b"\x00")[0].decode("utf-8", "replace")
        out = {"name": name, "size": len(val)}
        if len(val) >= 4:
            flags, xdata_len = struct.unpack_from("<HH", val, 0)
            if flags & ApfsVolume.XATTR_DATA_EMBEDDED:
                data = val[4:4 + xdata_len]
                if len(data) == xdata_len:
                    out["size"] = xdata_len
                    out["value"] = data
        return out

    def _size_of(self, oid, recs):
        ino = recs["inode"].get(oid)
        if ino and ino.get("size") is not None:
            return ino["size"]
        ext = recs["extent"].get(oid) or []
        return sum(e["length"] for e in ext)

    def listdir(self, oid=ROOT_DIR_OID, path="/"):
        recs = self._catalog()
        out = []
        for d in recs["drec"].get(oid or ROOT_DIR_OID, []):
            ino = recs["inode"].get(d["file_id"], {})
            is_dir = ino.get("is_dir", d["kind"] == 4)
            size = 0 if is_dir else self._size_of(d["file_id"], recs)
            out.append({
                "name": d["name"], "path": path.rstrip("/") + "/" + d["name"],
                "oid": d["file_id"], "is_dir": is_dir,
                "deleted": False,
                "size": size,
                "created": ino.get("created"), "modified": ino.get("modified"),
                "accessed": ino.get("accessed"), "changed": ino.get("changed"),
                "added": d["added"],
                "uid": ino.get("uid"), "gid": ino.get("gid"),
                "streams": [{"name": x["name"], "size": x["size"]}
                            for x in recs["xattr"].get(d["file_id"], [])],
                "id": "apfs:%d" % d["file_id"],
            })
        out.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
        return out

    def runs(self, oid):
        recs = self._catalog()
        ext = sorted(recs["extent"].get(oid, []), key=lambda e: e["logical"])
        size = self._size_of(oid, recs)
        out = []
        remaining = size
        for e in ext:
            out.append({
                "offset": e["phys"] * self.block_size,
                "length": e["length"],
                "block": e["phys"],
                "blocks": max(1, e["length"] // self.block_size),
                "logical": e["logical"],
                "sparse": e["phys"] == 0,
                "used": max(0, min(e["length"], remaining)),
            })
            remaining -= e["length"]
        return out

    def read_file(self, entry, max_bytes=None, stream=""):
        if stream:
            raise UnsupportedStream("APFS", stream)
        oid = entry.get("oid")
        if oid is None:
            return b""
        size = entry.get("size") or self._size_of(oid, self._catalog())
        limit = size if max_bytes is None else min(size, max_bytes)
        out = bytearray()
        for r in self.runs(oid):
            if len(out) >= limit:
                break
            take = min(r["length"], limit - len(out))
            if r["sparse"]:
                out += b"\x00" * take
            else:
                out += self.source.read_at(r["offset"], take)
        return bytes(out[:limit])

    def read_range(self, entry, off, length, stream=""):
        if stream:
            raise UnsupportedStream("APFS", stream)
        oid = entry.get("oid")
        if oid is None:
            return b""
        size = entry.get("size") or self._size_of(oid, self._catalog())
        return read_runs(self.source, self.runs(oid), off,
                         min(length, max(0, size - off)))

    def stat(self, entry):
        recs = self._catalog()
        oid = entry.get("oid")
        ino = recs["inode"].get(oid, {})
        info = {
            "filesystem": "APFS", "cluster_size": self.block_size,
            "object_id": oid, "parent": ino.get("parent"),
            "private_id": ino.get("private_id"),
            "mode": "0o%o" % ino.get("mode", 0),
            "uid": ino.get("uid"), "gid": ino.get("gid"),
            "volume": self.label,
        }
        if not entry.get("is_dir"):
            runs = self.runs(oid)
            if runs:
                info["runs"] = runs
                size = entry.get("size") or 0
                tail = size % self.block_size
                if tail:
                    last = runs[-1]
                    info["slack"] = {
                        "offset": last["offset"] + last["length"]
                        - (self.block_size - tail),
                        "length": self.block_size - tail}
            else:
                info["note"] = ("No file extents. The content may be stored in "
                                "an extended attribute (small files and "
                                "compressed files often are) or the file may "
                                "be a clone sharing another file's extents.")
        if self.encrypted:
            info["note"] = ("Volume is encrypted. Extents point at ciphertext; "
                            "this build does not decrypt.")
        if recs["xattr"].get(oid):
            info["xattrs"] = xattr_mod.for_client(recs["xattr"][oid])
        if ino and ino.get("size") is None and recs["extent"].get(oid):
            info["note"] = ("No data stream field on this inode, so the size "
                            "shown is the total of its extents and is rounded "
                            "up to the block size.")
        return info

    def info(self):
        return {
            "type": "APFS", "label": self.label, "uuid": self.uuid,
            "cluster_size": self.block_size, "block_size": self.block_size,
            "container": self.c.nx["uuid"],
            "transaction": self.xid,
            "files": self.num_files, "directories": self.num_dirs,
            "blocks_allocated": self.alloc_count,
            "last_unmount": self.unmount_time,
            "encrypted": self.encrypted,
            "catalog_root": self.root_tree_oid,
            "objects_mapped": len(self.omap),
            "findings": list(self.c.findings) + list(self.findings),
        }

    def allocated_extents(self):
        recs = self._catalog()
        out = []
        for oid, ext in recs["extent"].items():
            for e in ext:
                if e["phys"]:
                    out.append((e["phys"] * self.block_size,
                                e["phys"] * self.block_size + e["length"]))
        return out
