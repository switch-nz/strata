"""Build synthetic Windows event logs (.evtx) in memory.

Records are plain binary XML (no templates): a fragment header, then
elements whose names are written inline, attributes and string values,
which is enough to carry System/EventID, Provider@Name, TimeCreated
@SystemTime, Channel, Computer and EventData/Data[@Name] fields.
"""

import struct

CHUNK_SIZE = 65536
HEADER_SIZE = 4096
CHUNK_HEADER = 512


class _Payload:
    def __init__(self, at):
        self.at = at            # chunk offset of the payload's first byte
        self.b = bytearray(b"\x0f\x01\x01\x00")

    def _name(self, name):
        # The name structure sits inline, directly after the 4-byte offset
        # that points at it.
        here = self.at + len(self.b) + 4
        self.b += struct.pack("<I", here)
        u = name.encode("utf-16-le")
        self.b += struct.pack("<IHH", 0, 0, len(name)) + u + b"\x00\x00"

    def _string(self, text):
        u = text.encode("utf-16-le")
        self.b += b"\x05\x01" + struct.pack("<H", len(text)) + u

    def element(self, name, attrs=None, text=None, children=()):
        attrs = list((attrs or {}).items())
        self.b += bytes([0x41 if attrs else 0x01]) + struct.pack("<HI", 0, 0)
        self._name(name)
        if attrs:
            self.b += struct.pack("<I", 0)
            for i, (k, v) in enumerate(attrs):
                self.b += bytes([0x46 if i < len(attrs) - 1 else 0x06])
                self._name(k)
                self._string(str(v))
        if text is None and not children:
            self.b += b"\x03"
            return
        self.b += b"\x02"
        if text is not None:
            self._string(str(text))
        for child in children:
            child(self)
        self.b += b"\x04"


def E(name, attrs=None, text=None, *children):
    return lambda p: p.element(name, attrs, text, children)


def event(event_id, provider, when, channel="Security", computer="WS01",
          level=4, data=None):
    """An Event element: System plus EventData/Data[@Name] values."""
    system = E("System", None, None,
               E("Provider", {"Name": provider}),
               E("EventID", None, str(event_id)),
               E("Level", None, str(level)),
               E("TimeCreated", {"SystemTime": when}),
               E("Channel", None, channel),
               E("Computer", None, computer))
    datas = [E("Data", {"Name": k}, str(v)) for k, v in (data or {}).items()]
    return E("Event", None, None, system, E("EventData", None, None, *datas))


def build_log(events, dirty=False):
    """events: list of element builders from event(). One chunk."""
    chunk = bytearray(CHUNK_SIZE)
    chunk[0:8] = b"ElfChnk\x00"
    rp = CHUNK_HEADER
    for rid, ev in enumerate(events, 1):
        p = _Payload(rp + 24)
        ev(p)
        p.b += b"\x00"
        size = 24 + len(p.b) + 4
        rec = (b"\x2a\x2a\x00\x00" + struct.pack("<IQQ", size, rid, 0)
               + bytes(p.b) + struct.pack("<I", size))
        chunk[rp:rp + size] = rec
        rp += size
    struct.pack_into("<QQQQ", chunk, 8, 1, len(events), 1, len(events))
    struct.pack_into("<I", chunk, 0x30, rp)
    head = bytearray(HEADER_SIZE)
    head[0:8] = b"ElfFile\x00"
    struct.pack_into("<QQQ", head, 8, 0, 0, len(events) + 1)
    struct.pack_into("<IHH", head, 32, 128, 1, 3)
    struct.pack_into("<HH", head, 40, HEADER_SIZE, 1)
    struct.pack_into("<I", head, 120, 1 if dirty else 0)
    return bytes(head) + bytes(chunk)
