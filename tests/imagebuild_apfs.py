#!/usr/bin/env python3
"""Build small synthetic APFS container images in memory for the unit tests.

Layout (block size 4096):

* NXSB at block 0 (xp_desc_blocks = 0, so no checkpoints are scanned).
* Container object map (single leaf b-tree) mapping VOL_OID -> live APSB.
* Live volume (APSB, xid 2): omap -> catalog root + snap-meta root +
  the backup APSB; catalog with live.txt; snap-meta b-tree with one
  snapshot "before-update" whose sblock points at the backup APSB.
* Backup APSB (xid 1) with its own omap (snapshot-time) mapping its own
  catalog root, which holds old.txt.

Every object carries a real Fletcher-64 checksum (the reader verifies it).
Variants: build_apfs_no_snapshots() (snap-meta oid 0) and
build_apfs_dataless() (snapshot flag 0x1).
"""

import struct

BLOCK_SIZE = 4096

NX_MAGIC = b"NXSB"
APFS_MAGIC = b"APSB"

OBJ_NX_SUPERBLOCK = 0x00000001
OBJ_BTREE_NODE = 0x0003
OBJ_OMAP = 0x0000000B
OBJ_FS = 0x0000000C
OBJ_FSTREE = 0x0000000D

BTNODE_ROOT = 0x0001
BTNODE_LEAF = 0x0002
BTNODE_FIXED_KV_SIZE = 0x0004

TYPE_INODE = 3
TYPE_XATTR = 4
TYPE_FILE_EXTENT = 8
TYPE_DIR_REC = 9
TYPE_SNAP_METADATA = 0x0B
TYPE_SNAP_NAME = 0x0C

SNAP_META_DATALESS = 0x1

VOL_OID = 0x402
CATALOG_OID = 0x404
SNAP_META_OID = 0x405
SNAP_SBLOCK_OID = 0x406
SNAP_CATALOG_OID = 0x407

LIVE_XID = 2
SNAP_XID = 1

SNAP_NAME = "before-update"
SNAP_TIME_NS = 1700000000 * 1_000_000_000
SNAP_TIME_ISO = "2023-11-14T22:13:20Z"

LIVE_TXT = b"live\n"
OLD_TXT = b"old\n"

UUID = bytes(range(16))
LABEL = b"strata-apfs"

# Physical block assignments (everything is a single 4096-byte block).
BLK_NX = 0
BLK_CONT_OMAP = 1
BLK_CONT_OMAP_TREE = 2
BLK_VOL = 3
BLK_VOL_OMAP = 4
BLK_VOL_OMAP_TREE = 5
BLK_CATALOG = 6
BLK_SNAP_META = 7
BLK_SNAP_SBLOCK = 8
BLK_SNAP_OMAP = 9
BLK_SNAP_OMAP_TREE = 10
BLK_SNAP_CATALOG = 11
BLK_LIVE_FILE = 12
BLK_OLD_FILE = 13
NEXT_FREE = 14


def seal(buf):
    """Write the Fletcher-64 checksum into the first 8 bytes of the block.

    Callers MUST build the block with an 8-byte zero prefix at offset 0
    (the checksum field).  The checksum is computed over the whole block
    (fletcher64 itself skips the first 8 bytes) and then written in place.
    """
    data = bytearray(buf)
    data[0:8] = struct.pack("<Q", fletcher64(bytes(data)))
    return bytes(data)


def fletcher64(buf):
    """The checksum apfs stores in the first 8 bytes of every object."""
    body = buf[8:]
    if len(body) % 4:
        body += b"\x00" * (4 - len(body) % 4)
    s1 = s2 = 0
    m = 0xFFFFFFFF
    for i in range(0, len(body), 4):
        w = struct.unpack("<I", body[i:i + 4])[0]
        s1 = (s1 + w) % m
        s2 = (s2 + s1) % m
    c1 = m - ((s1 + s2) % m)
    c2 = m - ((s1 + c1) % m)
    return (c2 << 32) | c1


def btree_leaf(oid, xid, subtype, kv, root=False):
    """One leaf b-tree node with variable-length kv entries.

    Layout: 8-byte cksum placeholder, 24-byte object header, flags/level/
    nkeys, toc fields, 56-byte header total, toc (n*8), keys, middle pad,
    values ending at val_end, and a 40-byte btree_info footer when root.
    Value voff = total - prefix (distance from val_end to the value start).
    """
    n = len(kv)
    flags = BTNODE_LEAF | BTNODE_ROOT if root else BTNODE_LEAF
    hdr = b"\x00" * 8                                  # cksum field
    hdr += struct.pack("<QQII", oid, xid, OBJ_BTREE_NODE, subtype)
    hdr += struct.pack("<HHI", flags, 0, n)
    hdr += struct.pack("<HH", 0, n * 8)                # toc_off, toc size
    hdr += b"\x00" * 12
    keys = b""
    koffs, kls = [], []
    for k, _ in kv:
        koffs.append(len(keys))
        kls.append(len(k))
        keys += k
    prefix = [0]
    for _, v in kv[:-1]:
        prefix.append(prefix[-1] + len(v))
    total = prefix[-1] + (len(kv[-1][1]) if kv else 0)
    toc = b"".join(struct.pack("<HHHH", koffs[i], kls[i],
                               total - prefix[i], len(kv[i][1]))
                   for i in range(n))
    val_area = b"".join(v for _, v in kv)
    front = hdr + toc + keys
    pad = BLOCK_SIZE - (40 if root else 0) - len(front) - len(val_area)
    body = front + b"\x00" * pad + val_area
    if root:
        body += b"\x00" * 40                           # btree_info footer
    return seal(body)


def omap_tree_node(oid, xid, pairs):
    """An omap leaf with FIXED kv entries (16-byte keys and values).

    Fixed-kv toc holds <HH> (koff, voff) pairs; the reader derives
    klen/vlen from successive toc entries (16 here).  Same layout as
    btree_leaf: header, toc, keys, pad, values ending at val_end, footer.
    """
    n = len(pairs)
    flags = BTNODE_LEAF | BTNODE_ROOT | BTNODE_FIXED_KV_SIZE
    hdr = b"\x00" * 8                                  # cksum field
    hdr += struct.pack("<QQII", oid, xid, OBJ_BTREE_NODE, OBJ_OMAP)
    hdr += struct.pack("<HHI", flags, 0, n)
    hdr += struct.pack("<HH", 0, n * 4)
    hdr += b"\x00" * 12
    keys = b""
    values = b""
    for i, (oid_k, blk, xid_k) in enumerate(pairs):
        keys += struct.pack("<QQ", oid_k, xid_k)
        values += struct.pack("<IIQ", 0, BLOCK_SIZE, blk)
    toc = b""
    for i in range(n):
        toc += struct.pack("<HH", i * 16, (n - 1 - i) * 16)
    front = hdr + toc + keys
    # Fixed-kv: ve = val_end - voff, voff_i = (n-1-i)*16, so value i
    # starts at val_end - (n-1-i)*16; entry 0 begins at
    # val_end - (n-1)*16 and the LAST value starts exactly at val_end.
    start = BLOCK_SIZE - 40 - (n - 1) * 16
    body = front + b"\x00" * (start - len(front)) + values
    body = body[:BLOCK_SIZE].ljust(BLOCK_SIZE, b"\x00")
    return seal(body)


def nxsb(xid=1, omap_oid=BLK_CONT_OMAP, fs_oids=(VOL_OID,)):
    buf = b"\x00" * 32
    buf += NX_MAGIC                                  # 32
    buf += struct.pack("<I", BLOCK_SIZE)             # 36
    buf += struct.pack("<Q", NEXT_FREE)              # 40 block_count
    buf += b"\x00" * 24                              # 48..72
    buf += UUID                                      # 72 uuid
    buf += struct.pack("<Q", 999)                    # 88 next_oid
    buf += struct.pack("<Q", xid + 1)                # 96 next_xid
    buf += struct.pack("<I", 0)                      # 104 xp_desc_blocks
    buf += b"\x00" * 4                               # 108
    buf += struct.pack("<Q", 0)                      # 112 xp_desc_base
    buf += b"\x00" * 16                              # 120..136
    buf += struct.pack("<I", 0)                      # 136 xp_desc_index
    buf += struct.pack("<I", 0)                      # 140 xp_desc_len
    buf += b"\x00" * 8                               # 144..152
    buf += struct.pack("<Q", 0)                      # 152 spaceman
    buf += struct.pack("<Q", omap_oid)               # 160 omap_oid
    buf += struct.pack("<Q", 0)                      # 168 reaper
    buf += b"\x00" * 4                               # 176..180
    buf += struct.pack("<I", 1)                      # 180 max_file_systems
    for oid in fs_oids:
        buf += struct.pack("<Q", oid)                # 184.. fs array
    return seal(buf[:BLOCK_SIZE].ljust(BLOCK_SIZE, b"\x00"))


def apsb(oid, xid, omap_oid, root_tree_oid, snap_meta_oid, label=LABEL):
    buf = b"\x00" * 32
    buf += APFS_MAGIC                                # 32
    buf += struct.pack("<I", 0)                      # 36 fs_index
    buf += struct.pack("<Q", 0)                      # 40 features
    buf += b"\x00" * 8                               # 48
    buf += struct.pack("<Q", 0)                      # 56 incompat
    buf += struct.pack("<Q", 0)                      # 64 unmount time
    buf += b"\x00" * 16                              # 72..88
    buf += struct.pack("<Q", NEXT_FREE)              # 88 alloc_count (junk ok)
    buf += b"\x00" * 20                              # 96..116
    buf += struct.pack("<I", 0)                      # 116 root_tree_type
    buf += b"\x00" * 8                               # 120
    buf += struct.pack("<Q", omap_oid)               # 128 omap_oid
    buf += struct.pack("<Q", root_tree_oid)          # 136 root_tree_oid
    buf += struct.pack("<Q", 0)                      # 144 extentref
    buf += struct.pack("<Q", snap_meta_oid)          # 152 snap_meta_oid
    buf += b"\x00" * 24                              # 160..184
    buf += struct.pack("<Q", 9)                      # 184 next_obj_id
    buf += struct.pack("<Q", 1)                      # 192 num_files
    buf += struct.pack("<Q", 1)                      # 200 num_dirs
    buf += b"\x00" * 32                              # 208..240
    buf += UUID                                      # 240 uuid
    buf += b"\x00" * (704 - 256)
    buf += label + b"\x00" * (256 - len(label))      # 704 label
    return seal(buf[:BLOCK_SIZE].ljust(BLOCK_SIZE, b"\x00"))


def inode_value(oid, parent, size, is_dir=False, mode=None):
    if mode is None:
        mode = (0o40755 if is_dir else 0o100644)
    xnum = 1
    xfields = struct.pack("<HH", xnum, 4 + 16)       # num entries, bytes used
    entry = struct.pack("<BBH", 8, 0, 16)            # type 8 = size, 16 bytes
    data = struct.pack("<QQ", size, size + BLOCK_SIZE)
    head = struct.pack("<QQ", parent, parent)        # parent, private_id
    head += struct.pack("<QQQQ", SNAP_TIME_NS, SNAP_TIME_NS,
                        SNAP_TIME_NS, SNAP_TIME_NS)
    head += struct.pack("<Q", 0)                     # flags
    head += struct.pack("<i", 1 if is_dir else 0)    # nchildren
    head += b"\x00" * 12                             # default_acl..bsd_flags
    head += struct.pack("<II", 1000, 1000)           # owner, group
    head += struct.pack("<H", mode)                  # mode at 80..82
    head += b"\x00" * 10                             # 82..92 pad to xfields
    return head + xfields + entry + data


def extent_value(length, paddr):
    """File-extent value: length+crypto in the first quad, physical block
    in the second; padded to 24 bytes as the reader demands."""
    return struct.pack("<QQQ", length & 0x00FFFFFFFFFFFFFF, paddr, 0)


def cat_kv():
    """Catalog entries for both trees: live and snapshot-time.

    Live catalog: inode 2 (root dir), inode 3 (live.txt, one extent),
    drec live.txt.  Snapshot catalog: inode 2, inode 3 (old.txt),
    drec old.txt.  Inode 3 differs per tree so each file resolves.
    """
    live = [
        (struct.pack("<Q", (TYPE_INODE << 60) | 2),
         inode_value(2, 0, 0, is_dir=True)),
        (struct.pack("<Q", (TYPE_INODE << 60) | 3),
         inode_value(3, 2, len(LIVE_TXT))),
        (drec_key("live.txt"),
         drec_value(3)),
        (struct.pack("<QQ", (TYPE_FILE_EXTENT << 60) | 3, 0),
         extent_value(len(LIVE_TXT), BLK_LIVE_FILE)),
    ]
    old = [
        (struct.pack("<Q", (TYPE_INODE << 60) | 2),
         inode_value(2, 0, 0, is_dir=True)),
        (struct.pack("<Q", (TYPE_INODE << 60) | 3),
         inode_value(3, 2, len(OLD_TXT))),
        (drec_key("old.txt"),
         drec_value(3)),
        (struct.pack("<QQ", (TYPE_FILE_EXTENT << 60) | 3, 0),
         extent_value(len(OLD_TXT), BLK_OLD_FILE)),
    ]
    return live, old


def drec_key(name):
    """Directory-record key: packed oid at 0..8, then a u32 at 8..12
    whose low 10 bits hold the name length (NUL included), then the
    NUL-terminated name."""
    raw = name.encode()
    return struct.pack("<Q", (TYPE_DIR_REC << 60) | 2) \
        + struct.pack("<I", len(raw) + 1) + raw + b"\x00"


def drec_value(file_id, kind=1):
    return struct.pack("<QQH", file_id, SNAP_TIME_NS, kind) + b"\x00" * 6


def snap_meta_value(sblock_oid, flags):
    v = struct.pack("<QQ", 0, sblock_oid)            # extentref, sblock
    v += struct.pack("<QQ", SNAP_TIME_NS, SNAP_TIME_NS)
    v += struct.pack("<Q", 3)                        # inum
    v += struct.pack("<II", 0, flags)                # extentref type, flags
    v += struct.pack("<H", len(SNAP_NAME) + 1)
    v += SNAP_NAME.encode() + b"\x00"
    return v


def snap_meta_kv(flags=0, sblock_oid=SNAP_SBLOCK_OID):
    return [
        (struct.pack("<Q", (TYPE_SNAP_METADATA << 60) | SNAP_XID),
         snap_meta_value(sblock_oid, flags)),
        (struct.pack("<QH", (TYPE_SNAP_NAME << 60), len(SNAP_NAME) + 1)
         + SNAP_NAME.encode() + b"\x00",
         struct.pack("<Q", SNAP_XID)),
    ]


def omap_superblock(oid, xid, tree_oid):
    """Object-map superblock: 8-byte cksum slot, object header, and the
    tree oid at offset 48 where the reader reads it."""
    buf = b"\x00" * 8                                # cksum field
    buf += struct.pack("<QQII", oid, xid, OBJ_OMAP, 0)   # 8..32
    buf += b"\x00" * 16                              # 32..48
    buf += struct.pack("<Q", tree_oid)               # 48..56 tree oid
    return seal(buf[:BLOCK_SIZE].ljust(BLOCK_SIZE, b"\x00"))


def build_image(snap_meta_pairs, live_pairs, snap_omap_present=True):
    """Assemble the container from prepared record sets."""
    out = bytearray(NEXT_FREE * BLOCK_SIZE)
    put = lambda blk, data: out.__setitem__(
        slice(blk * BLOCK_SIZE, (blk + 1) * BLOCK_SIZE), data)

    put(BLK_NX, nxsb(omap_oid=BLK_CONT_OMAP))
    put(BLK_CONT_OMAP_TREE, omap_tree_node(
        0x101, LIVE_XID, [(VOL_OID, BLK_VOL, LIVE_XID)]))
    put(BLK_CONT_OMAP, omap_superblock(0x100, LIVE_XID, BLK_CONT_OMAP_TREE))

    put(BLK_VOL, apsb(VOL_OID, LIVE_XID, BLK_VOL_OMAP, CATALOG_OID,
                      SNAP_META_OID if snap_meta_pairs else 0))
    put(BLK_VOL_OMAP_TREE, omap_tree_node(
        0x102, LIVE_XID, live_pairs))
    put(BLK_VOL_OMAP, omap_superblock(0x102, LIVE_XID, BLK_VOL_OMAP_TREE))

    put(BLK_CATALOG, btree_leaf(
        CATALOG_OID, LIVE_XID, OBJ_FSTREE, LIVE_CATALOG, root=True))

    if snap_meta_pairs:
        put(BLK_SNAP_META, btree_leaf(
            SNAP_META_OID, LIVE_XID, OBJ_FSTREE, snap_meta_pairs, root=True))
        put(BLK_SNAP_SBLOCK, apsb(SNAP_SBLOCK_OID, SNAP_XID,
                                  BLK_SNAP_OMAP, SNAP_CATALOG_OID,
                                  0, label=LABEL))
        if snap_omap_present:
            put(BLK_SNAP_OMAP_TREE, omap_tree_node(
                0x103, SNAP_XID, SNAP_OMAP_PAIRS))
            put(BLK_SNAP_OMAP, omap_superblock(
                0x103, SNAP_XID, BLK_SNAP_OMAP_TREE))
        put(BLK_SNAP_CATALOG, btree_leaf(
            SNAP_CATALOG_OID, SNAP_XID, OBJ_FSTREE, OLD_CATALOG, root=True))

    put(BLK_LIVE_FILE, LIVE_TXT.ljust(BLOCK_SIZE, b"\x00"))
    put(BLK_OLD_FILE, OLD_TXT.ljust(BLOCK_SIZE, b"\x00"))
    return bytes(out)


LIVE_CATALOG, OLD_CATALOG = cat_kv()

# volume-omap mappings for the live volume: catalog + snap-meta + backup sb
LIVE_OMAP_PAIRS = [
    (CATALOG_OID, BLK_CATALOG, LIVE_XID),
    (SNAP_META_OID, BLK_SNAP_META, LIVE_XID),
    (SNAP_SBLOCK_OID, BLK_SNAP_SBLOCK, LIVE_XID),
]
# the snapshot-time omap maps the snapshot's own catalog root
SNAP_OMAP_PAIRS = [(SNAP_CATALOG_OID, BLK_SNAP_CATALOG, SNAP_XID)]


def build_apfs():
    """Full image: live volume + one readable snapshot "before-update"."""
    return build_image(snap_meta_kv(), LIVE_OMAP_PAIRS)


def build_apfs_no_snapshots():
    """Same container but the volume has no snapshot metadata tree."""
    return build_image(None, [
        (CATALOG_OID, BLK_CATALOG, LIVE_XID),
    ])


def build_apfs_dataless():
    """Snapshot flagged dataless (0x1): metadata only, no file contents."""
    return build_image(snap_meta_kv(flags=SNAP_META_DATALESS),
                       LIVE_OMAP_PAIRS)