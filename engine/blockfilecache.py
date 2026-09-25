"""Chromium's blockfile HTTP cache (net/disk_cache/blockfile), read directly.

Chrome and Edge on Windows write web content in this format: a folder of
``index``, ``data_0`` .. ``data_3`` and ``f_XXXXXX`` files. Every structure
below is from Chromium's own headers (disk_format_base.h, disk_format.h,
addr.h) and http_response_info.cc.

* A **block file** (``data_N``) is an 8192-byte header (magic 0xC104CAC3,
  the block size, and an allocation bitmap) followed by equal-size blocks.
  ``data_0`` holds 36-byte rankings nodes, ``data_1`` 256-byte blocks
  (entries), ``data_2`` 1 KB blocks and ``data_3`` 4 KB blocks; a full file
  chains to a further one.
* A **cache address** is a 32-bit value: bit 31 set when initialised, bits
  28-30 the file type, and for a block file bits 24-25 the block count less
  one, bits 16-23 the file number and bits 0-15 the first block. A
  separate-file address holds the number of an ``f_%06x`` file instead.
* An **entry** is a 256-byte ``EntryStore`` (up to four consecutive blocks
  when its key is long): the key's hash, state (normal, evicted, doomed),
  creation time, key length, four stream sizes and four stream addresses.
  The key is inline at offset 96, or at ``long_key`` past 927 bytes. Stream
  0 is the HTTP response info, stream 1 the body.
* Stream 0 is a Pickle: flags, request and response time, then the raw
  response headers as one length-prefixed string of NUL-separated lines.

The index is not needed: entries are found by walking the entry block files
themselves. That also finds entries the index no longer lists (doomed or
evicted, or in blocks since freed), each marked as such, which is evidence
the browser's own listing would not show. A block is taken as an entry only
if the whole structure is coherent; anything that is not is ignored, never
guessed at.
"""

import datetime
import struct

BLOCK_MAGIC = 0xC104CAC3
HEADER_SIZE = 8192
ENTRY_BLOCK = 256
MAX_INTERNAL_KEY = 4 * ENTRY_BLOCK - 96 - 1

_HEADER = struct.Struct("<IIhhiii4i4ii5i")           # 80 bytes, then bitmap
_ENTRY = struct.Struct("<IIIiiiQiI4i4II4iI")         # 96 bytes, then key
_RANKINGS = struct.Struct("<QQIIIiI")                # 36 bytes

FILE_EXTERNAL, FILE_RANKINGS = 0, 1
_BLOCK_SIZE = {1: 36, 2: 256, 3: 1024, 4: 4096}
STATES = {0: None, 1: "evicted", 2: "doomed"}

_EPOCH = datetime.datetime(1601, 1, 1)
# base::Time microseconds since 1601: accept 2000 .. 2200.
_TIME_MIN, _TIME_MAX = 12591158400 * 10 ** 6, 18906480000 * 10 ** 6

_CHUNK_BLOCKS = 4096
_MAX_ENTRIES = 200000


def chromium_time(us):
    """A base::Time internal value (microseconds since 1601-01-01) as an
    ISO-8601 UTC string, or None when it is zero or implausible."""
    if not us or not _TIME_MIN <= us <= _TIME_MAX:
        return None
    try:
        return (_EPOCH + datetime.timedelta(microseconds=us)).isoformat() + "Z"
    except (OverflowError, ValueError):
        return None


def decode_addr(value):
    """CacheAddr -> (file_type, file_number, start_block, num_blocks), or
    None when it is not an initialised address."""
    if not value & 0x80000000:
        return None
    ftype = (value & 0x70000000) >> 28
    if ftype == FILE_EXTERNAL:
        return ftype, value & 0x0FFFFFFF, 0, 0
    if ftype not in _BLOCK_SIZE:
        return None
    return (ftype, (value & 0x00FF0000) >> 16, value & 0xFFFF,
            ((value & 0x03000000) >> 24) + 1)


class Files:
    """The files of one cache folder, by lower-cased name. Each value has
    ``size`` and ``read_at(offset, length)``."""

    def __init__(self, files):
        self.files = {k.lower(): v for k, v in files.items()}

    def read(self, name, offset, length):
        f = self.files.get(name)
        if f is None or offset < 0 or length < 0 or offset + length > f.size:
            return None
        try:
            data = f.read_at(offset, length)
        except Exception:
            return None
        return data if len(data) == length else None

    def stream(self, addr, size):
        """Bytes of a stream stored at a cache address, or None."""
        a = decode_addr(addr)
        if a is None or size < 0:
            return None
        ftype, number, start, blocks = a
        if ftype == FILE_EXTERNAL:
            return self.read("f_%06x" % number, 0, size)
        bs = _BLOCK_SIZE[ftype]
        if size > blocks * bs:
            return None
        return self.read("data_%d" % number, HEADER_SIZE + start * bs, size)


def _block_file(files, name):
    """(header fields, allocation bitmap, block count) of an entry block
    file, or None if it is not a 256-byte-block file."""
    head = files.read(name, 0, HEADER_SIZE)
    if head is None:
        return None
    (magic, _version, this_file, _next, entry_size, _n, _max, *_rest
     ) = _HEADER.unpack_from(head, 0)
    if magic != BLOCK_MAGIC or entry_size != ENTRY_BLOCK:
        return None
    size = files.files[name].size
    return head[_HEADER.size:], (size - HEADER_SIZE) // ENTRY_BLOCK


def _allocated(bitmap, index, blocks):
    """BlockHeader::UsedMapBlock: bits are per block, low bit first."""
    for b in range(index, index + blocks):
        byte = b // 8
        if byte >= len(bitmap) or not bitmap[byte] >> (b % 8) & 1:
            return False
    return True


def _key(files, rec, block_index, name):
    """(key text, blocks the entry occupies) for an entry record, or None
    when the key is not coherent."""
    (_h, _n, _r, _ru, _rf, _st, _ct, key_len, long_key, *_rest
     ) = _ENTRY.unpack_from(rec, 0)
    if key_len <= 0:
        return None
    if key_len <= MAX_INTERNAL_KEY:
        blocks = (96 + key_len + 1 + ENTRY_BLOCK - 1) // ENTRY_BLOCK
        data = files.read(name, HEADER_SIZE + block_index * ENTRY_BLOCK,
                          blocks * ENTRY_BLOCK)
        if data is None:
            return None
        raw = data[96:96 + key_len]
        if data[96 + key_len:97 + key_len] != b"\0":
            return None
    else:
        blocks = 1
        a = decode_addr(long_key)
        if a is None:
            return None
        ftype, number, start, _n = a
        if ftype == FILE_EXTERNAL:
            raw = files.read("f_%06x" % number, 0, key_len)
        else:
            raw = files.read("data_%d" % number,
                             HEADER_SIZE + start * _BLOCK_SIZE[ftype],
                             key_len)
        if raw is None:
            return None
    if any(c < 0x20 or c == 0x7F for c in raw):
        return None
    return raw.decode("utf-8", "replace"), blocks


def _response(data):
    """Stream 0 (HttpResponseInfo, a Pickle) -> (request time, response
    time, header lines) or None. Only version 3 is written."""
    if data is None or len(data) < 8:
        return None
    (payload,) = struct.unpack_from("<I", data, 0)
    body = data[4:4 + payload]
    if payload > len(data) - 4 or len(body) < 4:
        return None
    (flags,) = struct.unpack_from("<I", body, 0)
    pos = 4
    extra = 0
    if flags & 0x80000000:
        if len(body) < pos + 4:
            return None
        (extra,) = struct.unpack_from("<I", body, pos)
        pos += 4
    if flags & 0xFF != 3 or len(body) < pos + 16:
        return None
    request, response = struct.unpack_from("<qq", body, pos)
    pos += 16
    if extra & 0x4:                     # original response time
        pos += 8
    if len(body) < pos + 4:
        return None
    (length,) = struct.unpack_from("<i", body, pos)
    pos += 4
    if length < 0 or len(body) < pos + length:
        return None
    lines = [x for x in body[pos:pos + length].split(b"\0")]
    while lines and not lines[-1]:
        lines.pop()
    return request, response, lines


def entries(files):
    """Every coherent entry in the folder's entry block files, as dicts:
    key, state, allocated, creation, refetch/reuse counts, stream sizes,
    stream 0 bytes (or None), last_used, and where it was found. Also
    returns the number of sparse child entries left out."""
    out, sparse = [], 0
    for name in sorted(n for n in files.files if n.startswith("data_")):
        info = _block_file(files, name)
        if info is None:
            continue
        bitmap, nblocks = info
        for chunk_start in range(0, nblocks, _CHUNK_BLOCKS):
            count = min(_CHUNK_BLOCKS, nblocks - chunk_start)
            data = files.read(name, HEADER_SIZE + chunk_start * ENTRY_BLOCK,
                              count * ENTRY_BLOCK)
            if data is None:
                break
            for i in range(count):
                rec = data[i * ENTRY_BLOCK:(i + 1) * ENTRY_BLOCK]
                e = _candidate(files, rec, name, chunk_start + i, bitmap)
                if e is None:
                    continue
                if e["key"].startswith("Range_"):
                    sparse += 1
                    continue
                out.append(e)
                if len(out) >= _MAX_ENTRIES:
                    return out, sparse
    return out, sparse


def _candidate(files, rec, name, index, bitmap):
    (_hash, _next, rank, reuse, refetch, state, created, key_len, _long,
     s0, s1, s2, s3, a0, a1, a2, a3, _flags, *_pad
     ) = _ENTRY.unpack_from(rec, 0)
    if state not in STATES or key_len <= 0:
        return None
    ra = decode_addr(rank)
    if ra is None or ra[0] != FILE_RANKINGS:
        return None
    if not _TIME_MIN <= created <= _TIME_MAX:
        return None
    sizes, addrs = (s0, s1, s2, s3), (a0, a1, a2, a3)
    if any(s < 0 for s in sizes) or any(
            a and not a & 0x80000000 for a in addrs):
        return None
    if not addrs[0] & 0x80000000:
        return None                       # no response info stored
    k = _key(files, rec, index, name)
    if k is None:
        return None
    key, blocks = k
    last_used = None
    node = files.read("data_%d" % ra[1],
                      HEADER_SIZE + ra[2] * _BLOCK_SIZE[FILE_RANKINGS],
                      _RANKINGS.size)
    if node is not None:
        last_used = _RANKINGS.unpack(node)[0]
    return {
        "key": key, "state": STATES[state],
        "allocated": _allocated(bitmap, index, blocks),
        "created": created, "last_used": last_used,
        "reuse_count": reuse, "refetch_count": refetch,
        "sizes": sizes, "stream0": files.stream(addrs[0], sizes[0]),
        "file": name, "offset": HEADER_SIZE + index * ENTRY_BLOCK,
    }
