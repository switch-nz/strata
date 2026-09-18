"""Reads a volume region as of a VSS snapshot by layering the store block
lists most-recent-first over the current volume, exactly what
engine.vss.snapshots() already enumerates.

First-cut limitations (see tests/test_vssstore.py for what is covered):
reverse block lists (type 5 range entries) and store-bitmap (type 6)
last-resort rules are not implemented -- a descriptor miss falls through to
the next (older) store in the chain, then to the live volume. Real VSS
stores written by Windows for the common same-size-volume case are covered
by the descriptor path. Validated against synthetic bytes only.
"""

import struct

from .vss import VSS_GUID, _guid


BLOCK = 0x4000
SUB = 512
FORWARDER, OVERLAY, IGNORE = 0x01, 0x02, 0x04
_HEADER = 128
_DESC = 32


class SnapshotReader:
    """Reads a volume region as of a VSS snapshot.

    source: the volume region reader (s.region(part, ev=ev)) -- anything
            with read_at(offset, length) + size (OffsetReader duck-type,
            ewf.py).
    block_list_offsets: store block-list offsets ordered MOST RECENT FIRST,
            ending at the wanted snapshot's own block_list_offset. For
            snapshot N out of M stores, pass snapshots[0..N]'s
            block_list_offsets (snapshot 0 = just its own).
    """

    def __init__(self, source, block_list_offsets):
        self.source = source
        self.size = source.size
        self.bytes_per_sector = getattr(source, "bytes_per_sector", 512)
        self.findings = []
        self._pos = 0
        self._layers = []
        for off in block_list_offsets:
            layer = self._load_block_list(off)
            if layer:
                self._layers.append(layer)
            elif off is not None:
                self.findings.append(
                    "Store block list at 0x%x is unreadable or malformed; "
                    "it was skipped as a layer." % off)

    # -- layer loading ------------------------------------------------------

    def _load_block_list(self, offset):
        """Parse one store's block-list chain into {original_offset:
        descriptor}; None if the first block is unreadable/malformed."""
        try:
            block = self.source.read_at(offset, BLOCK)
        except Exception:
            return None
        if len(block) < _HEADER:
            return None
        if _guid_ok(block[0:16]):
            pass
        else:
            return None
        version, rtype = struct.unpack_from("<II", block, 16)
        if version != 1 or rtype != 3:
            return None
        nxt = struct.unpack_from("<Q", block, 40)[0]
        table = {}
        self._descriptors(block, table)
        seen = {offset}
        hops = 0
        while nxt and nxt not in seen and hops < 256:
            seen.add(nxt)
            hops += 1
            try:
                block = self.source.read_at(nxt, BLOCK)
            except Exception:
                self.findings.append(
                    "Store block-list block at 0x%x is unreadable; the "
                    "chain was cut short." % nxt)
                break
            if len(block) < _HEADER or not _guid_ok(block[0:16]):
                self.findings.append(
                    "Store block-list block at 0x%x is malformed; the "
                    "chain was cut short." % nxt)
                break
            version, rtype = struct.unpack_from("<II", block, 16)
            if version != 1 or rtype != 3:
                self.findings.append(
                    "Store block-list block at 0x%x is not a descriptor "
                    "list; the chain was cut short." % nxt)
                break
            self._descriptors(block, table)
            nxt = struct.unpack_from("<Q", block, 40)[0]
        return table

    @staticmethod
    def _descriptors(block, table):
        pos = _HEADER
        end = len(block) - _DESC
        while pos <= end:
            orig, rel, sdb, flags, bitmap = struct.unpack_from(
                "<QQQII", block, pos)
            pos += _DESC
            if not (orig or rel or sdb or flags or bitmap):
                continue  # padding rows are zero-filled
            if flags & IGNORE:
                continue
            # A forwarder's relative offset maps to the original offset of
            # the next block; keep both sides of that mapping.
            key = rel if flags & FORWARDER else orig
            table[key] = (orig, rel, sdb, flags, bitmap)

    # -- reading ------------------------------------------------------------

    def read_at(self, offset, length):
        if offset < 0 or length <= 0 or offset >= self.size:
            return b""
        length = min(length, self.size - offset)
        out = bytearray()
        pos = offset
        end = offset + length
        while pos < end:
            n = min(BLOCK, end - pos)
            block_off = pos - (pos % BLOCK)
            start_in_block = pos - block_off
            out += self._read_block(block_off)[start_in_block:start_in_block
                                                + n]
            pos += n
        return bytes(out)

    def _read_block(self, block_off):
        for i, table in enumerate(self._layers):
            desc = table.get(block_off)
            if desc is None:
                continue
            orig, rel, sdb, flags, bitmap = desc
            if flags & FORWARDER:
                # The block's contents live in the next (older) store in
                # the chain; the descriptor's relative-store-offset field
                # gives that store's original offset.
                if i + 1 < len(self._layers):
                    older = self._layers[i + 1]
                    d2 = older.get(rel)
                    if d2 is not None:
                        o2, r2, s2, f2, b2 = d2
                        if f2 & FORWARDER:
                            pass
                        elif f2 & OVERLAY:
                            return self._read_overlay(older, block_off, o2,
                                                      s2, b2)
                        else:
                            return self._from_volume(s2)
                self.findings.append(
                    "Forwarder for block at 0x%x has no usable target; "
                    "the live volume was read instead." % block_off)
                return self._from_volume(block_off)
            if flags & OVERLAY:
                return self._read_overlay(table, block_off, orig, sdb,
                                          bitmap)
            return self._from_volume(sdb)
        return self._from_volume(block_off)

    def _read_overlay(self, table, block_off, orig, sdb, bitmap):
        """32-bit bitmap: bit i (LSB first) covers the i-th 512-byte
        sub-block; SET = stored in the store at sdb + i*512, CLEAR = the
        layer below (next store, else current volume)."""
        below = None
        for j, t in enumerate(self._layers):
            if t is table:
                below = self._layers[j + 1] if j + 1 < len(self._layers) \
                    else None
        out = bytearray()
        for i in range(BLOCK // SUB):
            if bitmap >> i & 1:
                out += self._from_volume(sdb + i * SUB, SUB)
            elif below is not None and block_off in below:
                o2, r2, s2, f2, b2 = below[block_off]
                if f2 & FORWARDER:
                    out += self._from_volume(block_off, SUB)
                elif f2 & OVERLAY:
                    out += self._from_volume(s2 + i * SUB, SUB)
                else:
                    out += self._from_volume(s2 + i * SUB, SUB)
            else:
                out += self._from_volume(block_off + i * SUB, SUB)
        return bytes(out)

    def _from_volume(self, offset, length=BLOCK):
        try:
            data = self.source.read_at(offset, length)
        except Exception:
            data = b""
        if len(data) < length:
            self.findings.append(
                "Bytes at 0x%x..0x%x are unreadable; zero-filled."
                % (offset, offset + length))
            data = data + b"\x00" * (length - len(data))
        return data[:length]

    # -- stream helpers, OffsetReader-compatible ----------------------------

    def read(self, n=-1):
        d = self.read_at(self._pos, self.size - self._pos if n < 0 else n)
        self._pos += len(d)
        return d

    def seek(self, off, whence=0):
        if whence == 0:
            self._pos = off
        elif whence == 1:
            self._pos += off
        else:
            self._pos = self.size + off
        return self._pos




def _guid_ok(b):
    return _guid(b) == VSS_GUID