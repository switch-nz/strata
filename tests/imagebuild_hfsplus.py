"""Build synthetic HFS+ volumes in memory.

Layout follows Apple's TN1150: a volume header at byte 1024, an allocation
bitmap, an extents overflow tree (empty), a catalog tree, and an attributes
tree, all as real B-trees (header node, leaf nodes, index nodes above them
when one leaf is not enough), then the files' forks. Every fork is one
contiguous extent.

Entries are described with File, Dir, Link (a hard link to an "indirect node"
file kept in the private metadata directory) and DirLink (a directory hard
link, as Time Machine makes). The inode number of a hard link is the catalog
ID of the file or folder it stands for, so those are given explicitly."""

import struct

MAC_EPOCH_OFFSET = 2082844800          # seconds from 1904 to 1970

PRIVATE_FILES = "\x00\x00\x00\x00HFS+ Private Data"
PRIVATE_DIRS = ".HFS+ Private Directory Data\r"

KIND_LEAF, KIND_INDEX, KIND_HEADER = 0xFF, 0x00, 0x01


class Node:
    def __init__(self, name):
        self.name = name


class File(Node):
    def __init__(self, name, data=b"", rsrc=b"", xattrs=None, owner_flags=0,
                 ftype=b"\x00" * 4, creator=b"\x00" * 4, flags=0, special=0,
                 cnid=None, times=None):
        Node.__init__(self, name)
        self.data, self.rsrc = data, rsrc
        self.xattrs = dict(xattrs or {})
        self.owner_flags = owner_flags
        self.ftype, self.creator = ftype, creator
        self.flags, self.special, self.cnid = flags, special, cnid
        self.times = times


class Dir(Node):
    def __init__(self, name, children=(), cnid=None, times=None):
        Node.__init__(self, name)
        self.children = list(children)
        self.cnid, self.times = cnid, times


class Link(File):
    """A hard link to file `inode`: an empty file record of type 'hlnk'."""

    def __init__(self, name, inode, times=None):
        File.__init__(self, name, ftype=b"hlnk", creator=b"hfs+",
                      flags=0x0020, special=inode, times=times)
        self.inode = inode


class DirLink(File):
    """A hard link to directory `inode`: a file record of type 'fdrp'."""

    def __init__(self, name, inode, times=None):
        File.__init__(self, name, ftype=b"fdrp", creator=b"MACS",
                      flags=0x0020, special=inode, times=times)
        self.inode = inode


# -- names and keys ------------------------------------------------------------

def uname(s):
    raw = s.encode("utf-16-be")
    return struct.pack(">H", len(raw) // 2) + raw


def fold(c):
    """HFS+ compares names case-insensitively; NUL sorts last."""
    if c == "\x00":
        return 0xFFFF
    return ord(c.lower()[0]) if ord(c) < 0x10000 else ord(c)


def cat_key(parent, name):
    body = struct.pack(">I", parent) + uname(name)
    return struct.pack(">H", len(body)) + body


def cat_sort(parent, name):
    return (parent, [fold(c) for c in name])


def attr_key(fid, name, start=0):
    body = struct.pack(">HIIH", 0, fid, start, len(name)) \
        + name.encode("utf-16-be")
    return struct.pack(">H", len(body)) + body


def attr_sort(fid, name, start=0):
    units = struct.unpack(">%dH" % len(name),
                          name.encode("utf-16-be")) if name else ()
    return (fid, list(units), start)


# -- B-trees ---------------------------------------------------------------------

def _pad2(n):
    return n + (n & 1)


def btree(records, node_size, max_key_len, attributes, reverse_leaves=False):
    """A B-tree file. `records` is [(sort key, key bytes, data bytes)]. With
    `reverse_leaves` the leaves are numbered from the highest node down, so the
    first leaf is the last node in the file, as it can be in a real tree."""
    records = sorted(records, key=lambda r: r[0])
    cap = node_size - 14

    def pack(kind, height, items, flink, blink):
        node = bytearray(node_size)
        node[8] = kind
        node[9] = height
        struct.pack_into(">H", node, 10, len(items))
        struct.pack_into(">II", node, 0, flink, blink)
        at, offs = 14, []
        for blob in items:
            offs.append(at)
            node[at:at + len(blob)] = blob
            at += _pad2(len(blob))
        offs.append(at)
        for i, o in enumerate(offs):
            struct.pack_into(">H", node, node_size - 2 * (i + 1), o)
        return bytes(node)

    def fit(items):
        """Split blobs into groups that each fit in a node."""
        groups, cur, used = [], [], 0
        for blob in items:
            need = _pad2(len(blob)) + 2
            if cur and used + need + 2 > cap:
                groups.append(cur)
                cur, used = [], 0
            cur.append(blob)
            used += need
        if cur:
            groups.append(cur)
        return groups

    leaf_items = []
    for _sort, key, data in records:
        leaf_items.append(key + (b"\x00" if len(key) & 1 else b"") + data)
    leaf_groups = fit(leaf_items) or [[]]
    # Node numbers: 0 header, 1..L leaves, then index levels.
    nodes = {}
    n_leaves = len(leaf_groups)
    first_keys = []
    i = 0
    for g, group in enumerate(leaf_groups):
        if reverse_leaves:
            num = n_leaves - g
            flink = num - 1 if g + 1 < n_leaves else 0
            blink = num + 1 if g else 0
        else:
            num = 1 + g
            flink = num + 1 if g + 1 < n_leaves else 0
            blink = num - 1 if g else 0
        nodes[num] = pack(KIND_LEAF, 1, group, flink, blink)
        first_keys.append((records[i][1] if records else b"", num))
        i += len(group)
    depth, level = 1, first_keys
    next_num = n_leaves + 1
    root = 1
    while len(level) > 1:
        depth += 1
        blobs = [k + struct.pack(">I", num) for k, num in level]
        groups = fit(blobs)
        new, i = [], 0
        for g, group in enumerate(groups):
            num = next_num
            next_num += 1
            nodes[num] = pack(KIND_INDEX, depth, group,
                              num + 1 if g + 1 < len(groups) else 0,
                              num - 1 if g else 0)
            new.append((level[i][0], num))
            i += len(group)
        level = new
        root = level[0][1]
    total = next_num
    header = bytearray(node_size)
    header[8] = KIND_HEADER
    struct.pack_into(">H", header, 10, 3)
    struct.pack_into(">HIIIIHHII", header, 14, depth, root if records else 0,
                     len(records),
                     (n_leaves if reverse_leaves else 1) if records else 0,
                     (1 if reverse_leaves else n_leaves) if records else 0,
                     node_size, max_key_len,
                     total, 0)
    header[14 + 39] = 0xCF                      # key compare: case folding
    struct.pack_into(">I", header, 14 + 40, attributes)
    # record offsets: header record, user data, map record
    offs = [14, 14 + 106, 14 + 106 + 128, node_size - 8]
    for i, o in enumerate(offs):
        struct.pack_into(">H", header, node_size - 2 * (i + 1), o)
    used = bytearray((total + 7) // 8)
    for n in range(total):
        used[n >> 3] |= 0x80 >> (n & 7)
    header[14 + 106 + 128:14 + 106 + 128 + len(used)] = used
    out = bytearray(header)
    for n in range(1, total):
        out += nodes[n]
    return bytes(out)


# -- the volume ------------------------------------------------------------------

def _mac(t=None):
    return (t if t is not None else 1_700_000_000) + MAC_EPOCH_OFFSET


def _fork(size, start, blocks):
    ext = struct.pack(">II", start, blocks) if blocks else b""
    return struct.pack(">QII", size, 0, blocks) + ext.ljust(64, b"\x00")


def _fork_extents(size, extents, blocks):
    """A fork with up to eight extents (start, count) held inline."""
    ext = b"".join(struct.pack(">II", a, n) for a, n in extents[:8])
    return struct.pack(">QII", size, 0, blocks) + ext.ljust(64, b"\x00")


def _perms(flags, special):
    return struct.pack(">IIBBHI", 501, 20, 0, flags, 0o100644, special)


def build(entries, block_size=4096, node_size=4096, name="TESTVOL",
          private_files=(), private_dirs=(), unmounted=True, fragment=(),
          reverse_leaves=False):
    """The volume image (bytes). `entries` are the root folder's children;
    `private_files` are File objects whose catalog ID is their inode number
    (kept in the private data folder, with their link counts set from the
    Link entries that name them) and `private_dirs` are Dir objects likewise
    for directory hard links."""
    root = Dir(name, entries)
    files_dir = dirs_dir = None
    if private_files:
        files_dir = Dir(PRIVATE_FILES, list(private_files))
        root.children.append(files_dir)
    if private_dirs:
        dirs_dir = Dir(PRIVATE_DIRS, list(private_dirs))
        root.children.append(dirs_dir)

    # link counts on the indirect nodes
    counts = {}

    def walk_links(d):
        for c in d.children:
            if isinstance(c, (Link, DirLink)):
                counts[c.inode] = counts.get(c.inode, 0) + 1
            elif isinstance(c, Dir):
                walk_links(c)
    walk_links(root)
    for f in private_files:
        f.special = counts.get(f.cnid, 0)

    # catalog IDs
    taken = {2}
    for d in (list(private_files) + list(private_dirs)):
        if d.cnid is not None:
            taken.add(d.cnid)
    nxt = [16]

    def assign(node):
        if node.cnid is None:
            while nxt[0] in taken:
                nxt[0] += 1
            node.cnid = nxt[0]
            taken.add(node.cnid)
            nxt[0] += 1
        if isinstance(node, Dir):
            for c in node.children:
                assign(c)
    root.cnid = 2
    for c in root.children:
        assign(c)

    # gather every file and folder with its parent
    items = []

    def collect(d):
        for c in d.children:
            items.append((d.cnid, c))
            if isinstance(c, Dir):
                collect(c)
    collect(root)
    files = [c for _p, c in items if isinstance(c, File)]
    folders = [root] + [c for _p, c in items if isinstance(c, Dir)]

    # block layout: block 0 holds the boot area and the volume header
    def blocks_for(n):
        return -(-n // block_size)

    cursor = [1]

    def take(nbytes):
        nb = blocks_for(nbytes)
        start = cursor[0]
        cursor[0] += nb
        return start, nb

    # catalog and attributes trees are built first to learn their sizes
    cat = []
    rec_time = _mac()
    for parent, c in items:
        t = _mac(c.times)
        if isinstance(c, Dir):
            val = len(c.children)
            data = struct.pack(">HHIIIIIII", 1, 0, val, c.cnid, t, t, t, t, 0)
            data += _perms(0, 0) + bytes(16) + bytes(16) + struct.pack(">II", 0, 0)
            cat.append((cat_sort(parent, c.name), cat_key(parent, c.name), data))
            thread = struct.pack(">HHI", 3, 0, parent) + uname(c.name)
            cat.append((cat_sort(c.cnid, ""), cat_key(c.cnid, ""), thread))
    # root folder record and thread
    rdata = struct.pack(">HHIIIIIII", 1, 0, len(root.children), 2, rec_time,
                        rec_time, rec_time, rec_time, 0)
    rdata += _perms(0, 0) + bytes(16) + bytes(16) + struct.pack(">II", 0, 0)
    cat.append((cat_sort(1, root.name), cat_key(1, root.name), rdata))
    cat.append((cat_sort(2, ""), cat_key(2, ""),
                struct.pack(">HHI", 3, 0, 1) + uname(root.name)))

    # attribute records
    attrs = []
    for f in files:
        for aname, value in f.xattrs.items():
            rec = struct.pack(">IIII", 0x10, 0, 0, len(value)) + value
            attrs.append((attr_sort(f.cnid, aname), attr_key(f.cnid, aname), rec))

    # place the forks, then write the file records
    image_parts = {}
    plan = {}
    # fixed system files first: bitmap (1 block per 32768*bs blocks) etc.
    # (their sizes depend on the total, so reserve generously)
    est_blocks = 64 + sum(blocks_for(len(f.data)) + blocks_for(len(f.rsrc))
                          for f in files)
    bitmap_bytes = (est_blocks + 7) // 8 + 8
    alloc = take(bitmap_bytes)
    extents_tree = btree([], node_size, 10, 0)
    ext = take(len(extents_tree))
    for f in files:
        d = take(len(f.data)) if f.data else (0, 0)
        r = take(len(f.rsrc)) if f.rsrc else (0, 0)
        plan[id(f)] = (d, r)
    for f in files:
        d, r = plan[id(f)]
        t = _mac(f.times)
        parent = next(p for p, c in items if c is f)
        data = struct.pack(">HHIIIIIII", 2, f.flags, 0, f.cnid, t, t, t, t, 0)
        data += _perms(f.owner_flags, f.special)
        data += f.ftype + f.creator + struct.pack(">H", 0) + bytes(6)
        data += bytes(16) + struct.pack(">II", 0, 0)
        data += _fork(len(f.data), *d) + _fork(len(f.rsrc), *r)
        cat.append((cat_sort(parent, f.name), cat_key(parent, f.name), data))
        cat.append((cat_sort(f.cnid, ""), cat_key(f.cnid, ""),
                    struct.pack(">HHI", 4, 0, parent) + uname(f.name)))
    cat_tree = btree(cat, node_size, 516, 0x6, reverse_leaves=reverse_leaves)
    attr_tree = btree(attrs, node_size, 266, 0x6) if attrs else None

    def place(tree, scatter):
        """[(start block, count)] for a system file of `tree`'s size."""
        if not tree:
            return []
        if not scatter:
            start, count = take(len(tree))
            return [(start, count)]
        out = []
        for _ in range(blocks_for(len(tree))):
            out.append((take(block_size)[0], 1))
            take(block_size)              # a gap, so no two are adjacent
        return out

    cat_ext = place(cat_tree, "catalog" in fragment)
    attr_ext = place(attr_tree, "attributes" in fragment)
    take(1024)                  # room for the alternate volume header
    total_blocks = cursor[0]

    img = bytearray(total_blocks * block_size)
    # bitmap
    bitmap = bytearray(alloc[1] * block_size)
    for n in range(total_blocks):
        bitmap[n >> 3] |= 0x80 >> (n & 7)
    img[alloc[0] * block_size:alloc[0] * block_size + len(bitmap)] = bitmap
    img[ext[0] * block_size:ext[0] * block_size + len(extents_tree)] = extents_tree
    def write(tree, extents):
        at = 0
        for start, count in extents:
            piece = tree[at:at + count * block_size]
            img[start * block_size:start * block_size + len(piece)] = piece
            at += count * block_size

    write(cat_tree, cat_ext)
    if attr_tree:
        write(attr_tree, attr_ext)

    # Extents beyond the eighth go in the extents overflow tree, keyed by the
    # system file's catalog ID (catalog 4, attributes 8) and the file block
    # each run starts at.
    overflow = []
    for cnid, extents in ((4, cat_ext), (8, attr_ext)):
        done = sum(n for _a, n in extents[:8])
        for i in range(8, len(extents), 8):
            group = extents[i:i + 8]
            key = struct.pack(">HBBII", 10, 0, 0, cnid, done)
            rec = b"".join(struct.pack(">II", a, n) for a, n in group)
            overflow.append(((cnid, 0, done), key, rec.ljust(64, b"\x00")))
            done += sum(n for _a, n in group)
    if overflow:
        extents_tree = btree(overflow, node_size, 10, 0)
        assert len(extents_tree) <= ext[1] * block_size
        img[ext[0] * block_size:ext[0] * block_size
            + len(extents_tree)] = extents_tree
    for f in files:
        d, r = plan[id(f)]
        if f.data:
            img[d[0] * block_size:d[0] * block_size + len(f.data)] = f.data
        if f.rsrc:
            img[r[0] * block_size:r[0] * block_size + len(f.rsrc)] = f.rsrc

    vh = bytearray(512)
    vh[0:2] = b"H+"
    struct.pack_into(">HI", vh, 2, 4, (1 << 8) if unmounted else 0)
    vh[8:12] = b"10.0"
    struct.pack_into(">IIII", vh, 16, rec_time, rec_time, 0, rec_time)
    struct.pack_into(">IIIII", vh, 32, len(files), len(folders) - 1,
                     block_size, total_blocks, 0)
    struct.pack_into(">I", vh, 64, max(taken) + 1)
    vh[112:192] = _fork(alloc[1] * block_size, *alloc)
    vh[192:272] = _fork(len(extents_tree), *ext)
    vh[272:352] = _fork_extents(
        len(cat_tree), cat_ext, sum(n for _a, n in cat_ext))
    vh[352:432] = _fork_extents(
        len(attr_tree) if attr_tree else 0, attr_ext,
        sum(n for _a, n in attr_ext))
    img[1024:1536] = vh
    img[len(img) - 1024:len(img) - 512] = vh
    return bytes(img)
