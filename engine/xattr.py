"""Decodes the two Apple extended attributes most relevant to an
examination -- both are plain data formats with no macOS API involved,
so decoding them is exactly as cross-platform as the rest of this
project.

com.apple.quarantine (LSQuarantine, set by Gatekeeper on anything
downloaded) is a semicolon-delimited ASCII string. kMDItemWhereFroms
(set by Safari, Chrome and most other browsers) is a binary property
list holding the URL a file was downloaded from, and often the page
that linked to it.

Everything else -- the resource fork, the Spotlight store, any other
attribute name -- is left alone; this only decodes what it can name a
byte layout for.
"""

import base64
import datetime
import plistlib

QUARANTINE = "com.apple.quarantine"
WHEREFROMS = "com.apple.metadata:kMDItemWhereFroms"

# LSQuarantine's timestamp is Core Foundation absolute time (seconds
# since 2001-01-01 UTC) -- a different epoch from HFS+'s own 1904-based
# catalog timestamps, so it needs its own conversion, not mactime().
_CF_EPOCH = datetime.datetime(2001, 1, 1, tzinfo=datetime.timezone.utc)


def _cftime(seconds):
    try:
        return (_CF_EPOCH + datetime.timedelta(seconds=seconds)).isoformat()
    except (OverflowError, ValueError, OSError):
        return None


def decode_quarantine(value):
    """The quarantine flag's own fields: flags;timestamp;agent;event_id,
    semicolon-delimited ASCII (e.g. "0083;5991b778;Safari;<uuid>"). Only
    the first three fields are guaranteed; the event id (a reference into
    ~/Library/Preferences/.../QuarantineEventsV2, not read here) is not
    always present. Returns None for anything that doesn't look like
    this shape, rather than a best guess."""
    try:
        text = bytes(value).decode("ascii")
    except UnicodeDecodeError:
        return None
    parts = text.split(";")
    if len(parts) < 3:
        return None
    flags_hex, stamp_hex, agent = parts[0], parts[1], parts[2]
    try:
        flags = int(flags_hex, 16)
    except ValueError:
        return None
    out = {"flags": "0x%04x" % flags, "agent": agent or None}
    try:
        out["downloaded_at"] = _cftime(int(stamp_hex, 16))
    except ValueError:
        out["downloaded_at"] = None
    if len(parts) > 3 and parts[3]:
        out["event_id"] = parts[3]
    return out


def decode_wherefroms(value):
    """A binary (or XML) property list holding an array of URL strings --
    usually [download URL, referring page]. Anything that doesn't decode
    to exactly that shape (a plist of strings) is not returned: a
    malformed or unexpected value should show as absent, not guessed at."""
    try:
        obj = plistlib.loads(bytes(value))
    except Exception:
        return None
    if isinstance(obj, list) and obj and all(isinstance(x, str) for x in obj):
        return obj
    return None

_DECODERS = {QUARANTINE: decode_quarantine, WHEREFROMS: decode_wherefroms}


def decode(name, value):
    """The decoded form of a named extended attribute's raw value, or
    None if the name isn't one of the two this module understands, or
    the value doesn't match that attribute's expected shape."""
    fn = _DECODERS.get(name)
    return fn(value) if fn is not None and value is not None else None


def for_client(xattrs):
    """The stat()-side {"name", "size", "value": <raw bytes>?} list a
    filesystem module builds, turned into what /api/stat actually sends:
    "value" base64-encoded (matching how every other raw-byte field in a
    stat() response already travels to the client), plus a "decoded"
    field wherever the name and value are both recognised. An entry with
    no captured value at all -- a large, fork-based attribute this
    project does not read the content of -- keeps only its name and
    size."""
    out = []
    for x in xattrs or ():
        row = {"name": x.get("name"), "size": x.get("size")}
        value = x.get("value")
        if value is not None:
            row["value"] = base64.b64encode(bytes(value)).decode("ascii")
            got = decode(x.get("name"), value)
            if got is not None:
                row["decoded"] = got
        out.append(row)
    return out
