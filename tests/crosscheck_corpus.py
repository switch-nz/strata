"""The synthetic images the cross-check runs over: the same builders the unit
tests use, so there is one description of each format in the repository. A
case is an image plus the name it should be given on disk (formats are
recognised partly by extension). An image that is not a valid example of its
format to a stricter reader is still included: the reader refusing it is a
finding about the builder, and the baseline says so, so it stays on the list
of things to improve rather than being quietly left out."""

import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class Case(object):

    def __init__(self, name, suffix, build, companions=None):
        self.id = "synthetic:" + name
        self.suffix = suffix
        self.build = build
        self.companions = companions or (lambda: {})


def _first(x):
    return x[0] if isinstance(x, (tuple, list)) else x


def _hfs(entries=None, **kw):
    import imagebuild_hfsplus as hb
    return hb.build(entries or [
        hb.Dir("Top", [hb.Dir("Inner", [hb.File("deep.txt", b"deep text")]),
                       hb.File("a.txt", b"first file")]),
        hb.File("root.txt", b"x" * 5000)], **kw)


def _hfs_links():
    import imagebuild_hfsplus as hb
    node = hb.File("iNode100", b"shared contents", cnid=100,
                   xattrs={"user.tag": b"on the node"})
    return hb.build(
        [hb.File("plain.txt", b"plain"),
         hb.Dir("sub", [hb.Link("second", 100)]), hb.Link("first", 100)],
        private_files=[node])


def _hfs_compressed():
    import imagebuild_decmpfs as dc
    import imagebuild_hfsplus as hb
    big = bytes((i * 7 + i // 251) & 0xFF for i in range(150000))
    small = b"held in the attribute " * 8
    xa = "com.apple.decmpfs"

    def packed(kind, data):
        if kind in (3, 7):
            codec = dc.zlib_block if kind == 3 else dc.lzvn_literals
            return dc.inline_value(kind, len(data), codec(data)), b""
        blocks = dc.split(data)
        fork = (dc.zlib_fork([dc.zlib_block(b) for b in blocks])
                if kind == 4 else
                dc.lzvn_fork([dc.lzvn_literals(b) for b in blocks]))
        return dc.header(kind, len(data)), fork

    entries = []
    for name, kind, data in (("z-inline", 3, small), ("z-fork", 4, big),
                             ("l-inline", 7, small), ("l-fork", 8, big)):
        value, fork = packed(kind, data)
        entries.append(hb.File(name, rsrc=fork, xattrs={xa: value},
                               owner_flags=0x20))
    return hb.build(entries)


def _hfs_fragmented():
    import imagebuild_hfsplus as hb
    return hb.build(
        [hb.Dir("Top", [hb.File("f%d.txt" % i, b"data%d" % i)
                        for i in range(250)])],
        fragment=("catalog",), reverse_leaves=True)


def _gpt_hfs():
    import imagebuild_gpt as g
    hfs = _hfs()
    sectors = -(-len(hfs) // 512)
    return g.build([(40, sectors, g.HFS, "first slot", hfs)],
                   40 + sectors + 100 + 34 + 1)[0]


def _gpt_ntfs():
    import imagebuild_ntfs as n
    return n.wrap_gpt(n.build_ntfs())


def _vhd_dynamic():
    import imagebuild_vhd
    return _first(imagebuild_vhd.sparse(
        5 * 4096, {0: (bytes(range(256)) * 16, None),
                   2: (b"\xA5" * 4096, None)}))


def _qcow2(version, pack):
    """A compressed cluster has to inflate to a whole cluster, as every real
    writer makes it; and the zero flag exists only from version 3."""
    def build():
        import imagebuild_qcow2
        clusters = {0: bytes(range(256)) * 16,
                    2: ("z", b"\xA5" * 4096),
                    4: ("z", (b"strata " * 500).ljust(4096, b"\0"))}
        if version >= 3:
            clusters[3] = "zero"
        return imagebuild_qcow2.build(5 * 4096, clusters, version=version,
                                      pack=pack)
    return build


def _vdi():
    import imagebuild_vdi
    return _first(imagebuild_vdi.build(
        5 * 4096, {0: bytes(range(256)) * 16, 2: b"\xA5" * 4096}, zero=(3,)))


def _dmg():
    import imagebuild_dmg
    rng = random.Random(1)
    disk = bytes(rng.choice(b"abcdefgh \n") for _ in range(512 * 48))
    return imagebuild_dmg.build([("disk image", 0, disk)])


def synthetic():
    import imagebuild_ewf
    import imagebuild_ext4
    import imagebuild_fat
    import imagebuild_apfs
    import imagebuild_ntfs
    import imagebuild_vmdk
    return [
        Case("ntfs", ".img", imagebuild_ntfs.build_ntfs),
        Case("ntfs.gpt", ".img", _gpt_ntfs),
        Case("fat12", ".img", lambda: imagebuild_fat.build_fat(12)),
        Case("fat16", ".img", lambda: imagebuild_fat.build_fat(16)),
        Case("ext4", ".img", imagebuild_ext4.build_ext4),
        Case("ext2", ".img", imagebuild_ext4.build_ext2_legacy),
        Case("apfs", ".img", imagebuild_apfs.build_apfs),
        Case("hfsplus", ".img", _hfs),
        Case("hfsplus.links", ".img", _hfs_links),
        Case("hfsplus.compressed", ".img", _hfs_compressed),
        Case("hfsplus.fragmented", ".img", _hfs_fragmented),
        Case("hfsplus.gpt", ".img", _gpt_hfs),
        Case("ewf", ".E01", lambda: _first(imagebuild_ewf.build_e01())),
        Case("vhd.dynamic", ".vhd", _vhd_dynamic),
        Case("qcow2.v2", ".qcow2", _qcow2(2, False)),
        Case("qcow2.v3.compressed", ".qcow2", _qcow2(3, True)),
        Case("vdi", ".vdi", _vdi),
        Case("vmdk.sparse", ".vmdk", imagebuild_vmdk.build_sparse),
        Case("vmdk.stream", ".vmdk",
             lambda: _first(imagebuild_vmdk.build_stream_optimized())),
        Case("dmg", ".dmg", _dmg),
    ]
