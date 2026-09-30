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


def _chunk(events):
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
        if rp + size > CHUNK_SIZE:
            raise ValueError("too many events for one chunk")
        chunk[rp:rp + size] = rec
        rp += size
    struct.pack_into("<QQQQ", chunk, 8, 1, len(events), 1, len(events))
    struct.pack_into("<I", chunk, 0x30, rp)
    return bytes(chunk)


def _header(records, chunks, dirty):
    head = bytearray(HEADER_SIZE)
    head[0:8] = b"ElfFile\x00"
    struct.pack_into("<QQQ", head, 8, 0, 0, records + 1)
    struct.pack_into("<IHH", head, 32, 128, 1, 3)
    struct.pack_into("<HH", head, 40, HEADER_SIZE, chunks)
    struct.pack_into("<I", head, 120, 1 if dirty else 0)
    return bytes(head)


def build_log(events, dirty=False):
    """events: list of element builders from event(). One chunk."""
    return _header(len(events), 1, dirty) + _chunk(events)


def build_log_chunks(groups, dirty=False):
    """A log of several chunks: `groups` is a list of event lists, one per
    chunk."""
    return (_header(sum(len(g) for g in groups), len(groups), dirty)
            + b"".join(_chunk(g) for g in groups))


# ---------------------------------------------------------------------------
# Template-based records. Real logs write most of a record as a template
# instance: a shared definition of the XML, plus a list of typed values
# substituted into it. The type of each value comes from the record's own
# descriptor, so one record can carry something unexpected in a field the
# others carry as text.

TEMPLATE_AT = 0x8000


class _TemplatePayload(_Payload):
    def sub_attr_el(self, name, attr, index, vtype):
        self.b += bytes([0x41]) + struct.pack("<HI", 0, 0)
        self._name(name)
        self.b += struct.pack("<I", 0)
        self.b += bytes([0x06])
        self._name(attr)
        self.b += bytes([0x0D]) + struct.pack("<HB", index, vtype)
        self.b += b"\x03"

    def sub_text_el(self, name, index, vtype):
        self.b += bytes([0x01]) + struct.pack("<HI", 0, 0)
        self._name(name)
        self.b += b"\x02" + bytes([0x0D]) + struct.pack("<HB", index, vtype)
        self.b += b"\x04"

    def open_el(self, name):
        self.b += bytes([0x01]) + struct.pack("<HI", 0, 0)
        self._name(name)
        self.b += b"\x02"


def _template_definition(provider):
    """Event/System with EventID, Level and SystemTime as substitutions 0-2;
    the provider is fixed text, or substitution 3 when `provider` is None."""
    p = _TemplatePayload(TEMPLATE_AT + 24)
    p.open_el("Event")
    p.open_el("System")
    if provider is None:
        p.sub_attr_el("Provider", "Name", 3, 0x01)
    else:
        p.element("Provider", {"Name": provider})
    p.sub_text_el("EventID", 0, 0x06)
    p.sub_text_el("Level", 1, 0x04)
    p.sub_attr_el("TimeCreated", "SystemTime", 2, 0x11)
    p.element("Channel", None, "Security")
    p.b += b"\x04\x04\x00"
    body = bytes(p.b)
    return struct.pack("<I", 0) + bytes(16) + struct.pack("<I", len(body)) + body


def filetime(year, month, day, hour, minute):
    import datetime
    delta = (datetime.datetime(year, month, day, hour, minute)
             - datetime.datetime(1601, 1, 1))
    return (delta.days * 86400 + delta.seconds) * 10 ** 7


def template_record(values):
    """A record instantiating the template with `values`, a list of
    (value type, raw bytes) in substitution order."""
    b = bytearray(b"\x0f\x01\x01\x00")
    b += b"\x0c\x01" + struct.pack("<II", 1, TEMPLATE_AT)
    b += struct.pack("<I", len(values))
    for vtype, raw in values:
        b += struct.pack("<HBB", len(raw), vtype, 0)
    for vtype, raw in values:
        b += raw
    return bytes(b) + b"\x00"


def template_event(event_id, when, level=4):
    """The usual record: UInt16 EventID, UInt8 Level, FILETIME time."""
    return template_record([(0x06, struct.pack("<H", event_id)),
                            (0x04, bytes([level])),
                            (0x11, struct.pack("<Q", when))])


def template_log(records, provider="Microsoft-Windows-Security-Auditing"):
    chunk = bytearray(CHUNK_SIZE)
    chunk[0:8] = b"ElfChnk\x00"
    rp = CHUNK_HEADER
    for rid, payload in enumerate(records, 1):
        size = 24 + len(payload) + 4
        chunk[rp:rp + size] = (
            b"\x2a\x2a\x00\x00"
            + struct.pack("<IQQ", size, rid, filetime(2024, 3, 1, 9, rid))
            + payload + struct.pack("<I", size))
        rp += size
    t = _template_definition(provider)
    chunk[TEMPLATE_AT:TEMPLATE_AT + len(t)] = t
    struct.pack_into("<QQQQ", chunk, 8, 1, len(records), 1, len(records))
    struct.pack_into("<I", chunk, 0x30, rp)
    head = bytearray(HEADER_SIZE)
    head[0:8] = b"ElfFile\x00"
    struct.pack_into("<QQQ", head, 8, 0, 0, len(records) + 1)
    struct.pack_into("<IHH", head, 32, 128, 1, 3)
    struct.pack_into("<HH", head, 40, HEADER_SIZE, 1)
    return bytes(head) + bytes(chunk)
