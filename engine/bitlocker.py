import hashlib
import struct
import uuid

from .crypto import aes, ccm

from .text import t as _t

STRETCH_ROUNDS = 0x100000

SIGNATURE = b"-FVE-FS-"

GUID_VISTA = uuid.UUID("{4967d63b-2e29-4ad8-8399-f6a339e3d00e}")
GUID_WIN7 = uuid.UUID("{4967d63b-2e29-4ad8-8399-f6a339e3d001}")
GUID_TOGO = uuid.UUID("{92a84d3b-dd80-4d0e-9e4e-b1e3284eaed8}")

ENCRYPTION_METHODS = {
    0x8000: ("AES-CBC 128 with Elephant diffuser", "cbc-diffuser", 16),
    0x8001: ("AES-CBC 256 with Elephant diffuser", "cbc-diffuser", 32),
    0x8002: ("AES-CBC 128", "cbc", 16),
    0x8003: ("AES-CBC 256", "cbc", 32),
    0x8004: ("AES-XTS 128", "xts", 16),
    0x8005: ("AES-XTS 256", "xts", 32),
}

PROTECTOR_TYPES = {
    # Numeric values verified against the libyal/libbde format specification
    # and cross-checked against bitlocker2john.c -- both agree TPM and
    # Startup key sit in the high byte (0x0100/0x0200), not 0x0001/0x0002 as
    # this dict originally had it, which meant a real .BEK-protected volume
    # never actually matched the "keyfile" entry below.
    0x0000: ("Clear key", "none",
             "The volume is not really protected — the key is stored beside "
             "it in the clear. This is what a volume looks like mid-encryption "
             "or with protection suspended."),
    0x0100: ("TPM", "tpm",
             "Sealed to the machine's TPM. It cannot be unlocked from an "
             "image; the chip is the secret and it did not come with the disk."),
    0x0200: ("Startup key", "keyfile",
             "Requires the .BEK startup key file, normally on a USB stick."),
    0x0500: ("TPM and PIN", "tpm",
             "Sealed to the TPM and additionally gated by a PIN. Not "
             "recoverable from an image alone."),
    0x0800: ("Recovery password", "recovery",
             "The 48-digit recovery key, in eight groups of six."),
    0x1000: ("Auto-unlock", "keyfile",
             "Unlocked automatically by another volume; the key lives in that "
             "volume's registry, not here."),
    0x2000: ("Password", "password", "A user password."),
}

ENTRY_VMK = 0x0002
ENTRY_FVEK = 0x0003
ENTRY_DESCRIPTION = 0x0007
ENTRY_VOLUME_HEADER = 0x000F
VALUE_KEY = 0x0001
VALUE_UNICODE = 0x0002
VALUE_STRETCH_KEY = 0x0003
VALUE_AES_CCM = 0x0005
VALUE_VMK = 0x0008
VALUE_EXTERNAL_KEY = 0x0009
VALUE_OFFSET_SIZE = 0x000F

class Unsupported(Exception):
    pass

def looks_like_bitlocker(head):
    return len(head) >= 11 and head[3:11] == SIGNATURE

def _guid(b):
    return uuid.UUID(bytes_le=b)

def _filetime(v):
    import datetime
    if not v:
        return None
    try:
        return (datetime.datetime(1601, 1, 1)
                + datetime.timedelta(microseconds=v // 10)).isoformat() + "Z"
    except (OverflowError, ValueError):
        return None

def _entries(data, pos, end, depth=0):
    out = []
    while pos + 8 <= end and depth < 8:
        size, etype, vtype, version = struct.unpack_from("<HHHH", data, pos)
        if size < 8 or pos + size > end:
            break
        body = data[pos + 8:pos + size]
        out.append({"entry_type": etype, "value_type": vtype,
                    "version": version, "data": body})
        pos += size
    return out

def _stretch(initial, salt, progress=None):
    last = b"\x00" * 32
    step = STRETCH_ROUNDS // 100
    for i in range(STRETCH_ROUNDS):
        last = hashlib.sha256(
            last + initial + salt + struct.pack("<Q", i)).digest()
        if progress and i % step == 0:
            progress(i / STRETCH_ROUNDS)
    if progress:
        progress(1.0)
    return last

def _ccm_open(key, blob):
    if len(blob) < 12 + 16 + 8:
        raise Unsupported(_t("bitlocker.key_blob_too_short"))
    nonce, mac, body = blob[:12], blob[12:28], blob[28:]
    plain = ccm.decrypt(key, nonce, body, mac)
    if len(plain) < 12:
        raise Unsupported(_t("bitlocker.unwrapped_key_entry_too"))
    size, etype, vtype, version = struct.unpack_from("<HHHH", plain, 0)
    return plain[12:size] if 12 < size <= len(plain) else plain[12:]

def parse_bek_file(data):
    """The raw 256-bit key out of a .BEK startup-key file: a 48-byte header
    (the same shape as the volume's own FVE metadata header) followed by one
    External Key (0x0009) entry -- a key identifier GUID, a last-modified
    FILETIME, then properties holding an optional description and a Key
    (0x0001) entry, which is a 4-byte encryption-method field followed by
    the raw key bytes themselves. Returns None for anything that doesn't
    match that shape, rather than guessing."""
    if len(data) < 48:
        return None
    meta_size = struct.unpack_from("<I", data, 0)[0]
    end = min(meta_size, len(data)) if meta_size >= 48 else len(data)
    for e in _entries(data, 48, end):
        if e["value_type"] != VALUE_EXTERNAL_KEY or len(e["data"]) < 24:
            continue
        for prop in _entries(e["data"], 24, len(e["data"])):
            if prop["value_type"] == VALUE_KEY and len(prop["data"]) > 4:
                return prop["data"][4:]
    return None

def _is_recovery_format(s):
    digits = "".join(c for c in s if c.isdigit())
    return len(digits) == 48 and all(c.isdigit() or c in "- " for c in s)

def _recovery_digits(s):
    groups = "".join(c if c.isdigit() else " " for c in s).split()
    if len(groups) == 1 and len(groups[0]) == 48:
        groups = [groups[0][i:i + 6] for i in range(0, 48, 6)]
    if len(groups) != 8 or any(len(g) != 6 for g in groups):
        return None
    out = bytearray()
    for g in groups:
        v = int(g)
        if v % 11:
            return None
        q = v // 11
        if q > 0xFFFF:
            return None
        out += struct.pack("<H", q)
    return bytes(out)

def diffuser_decrypt(data, tweak_key, offset, sector_size):
    if not tweak_key:
        raise Unsupported(
            _t("bitlocker.volume_uses_elephant_diffuser"))
    raise Unsupported(
        _t("bitlocker.elephant_diffuser_support_implemented"))

class Protector:

    def __init__(self, guid, changed, ptype, entries):
        self.guid = guid
        self.changed = changed
        self.type_id = ptype
        name, kind, note = PROTECTOR_TYPES.get(
            ptype, ("Unknown (0x%04X)" % ptype, "unknown",
                    "Unrecognised protector type."))
        self.name = name
        self.kind = kind
        self.note = note
        self.entries = entries
        self.description = None
        for e in entries:
            if e["value_type"] == VALUE_UNICODE:
                self.description = e["data"].decode("utf-16-le", "replace") \
                    .rstrip("\x00")

    @property
    def usable(self):
        return self.kind in ("password", "recovery", "none", "keyfile")

    def info(self):
        return {"guid": str(self.guid), "type": self.name, "kind": self.kind,
                "type_id": self.type_id, "note": self.note,
                "description": self.description, "changed": self.changed,
                "usable": self.usable}

class BitLocker:

    def __init__(self, source, size=None):
        self.source = source
        self.size = size if size is not None else getattr(source, "size", 0)
        self.valid = False
        self.findings = []
        self.protectors = []
        self.fvek = None
        self.method = None
        self.method_name = None
        self.mode = None
        self.key_bytes = None
        self.volume_header = None
        self._parse()

    def _parse(self):
        head = self.source.read_at(0, 512)
        if not looks_like_bitlocker(head):
            return
        self.sector_size = struct.unpack_from("<H", head, 0x0B)[0] or 512
        self.guid = _guid(head[0xA0:0xB0])
        if self.guid == GUID_VISTA:
            self.generation = "Vista"
            offsets = struct.unpack_from("<3Q", head, 0xB0)
        else:
            self.generation = ("Windows 7 or later"
                               if self.guid == GUID_WIN7 else
                               "BitLocker To Go" if self.guid == GUID_TOGO
                               else "unknown (%s)" % self.guid)
            offsets = struct.unpack_from("<3Q", head, 0xB0)
        self.metadata_offsets = [o for o in offsets if 0 < o < (self.size or 1 << 62)]
        if not self.metadata_offsets:
            self.findings.append(
                "The volume carries a BitLocker signature but no usable "
                "metadata offsets; the header may be damaged.")
            return

        for i, off in enumerate(self.metadata_offsets):
            try:
                if self._read_metadata(off):
                    if i:
                        self.findings.append(
                            "Metadata copy %d was used; copies before it did "
                            "not parse." % (i + 1))
                    self.valid = True
                    return
            except Exception:
                continue
        self.findings.append("None of the three metadata copies parsed.")

    def _read_metadata(self, offset):
        block = self.source.read_at(offset, 512)
        if len(block) < 64 or block[0:8] != SIGNATURE:
            return False
        size = struct.unpack_from("<H", block, 8)[0]
        blob = self.source.read_at(offset, max(size + 64, 4096))

        hdr = 64
        (meta_size, meta_version, hdr_size, copy_size) = struct.unpack_from(
            "<4I", blob, hdr)
        if meta_version not in (1, 2) or meta_size < 48 or meta_size > len(blob):
            return False
        self.volume_guid = _guid(blob[hdr + 16:hdr + 32])
        self.next_counter = struct.unpack_from("<I", blob, hdr + 32)[0]
        self.method = struct.unpack_from("<H", blob, hdr + 36)[0]
        self.created = _filetime(struct.unpack_from("<Q", blob, hdr + 40)[0])

        known = ENCRYPTION_METHODS.get(self.method)
        if known:
            self.method_name, self.mode, self.key_bytes = known
        else:
            self.method_name = "Unknown (0x%04X)" % self.method
            self.mode = None
            self.findings.append(
                "Unrecognised encryption method 0x%04X. The volume will not "
                "be decrypted rather than decrypted wrongly." % self.method)

        entries = _entries(blob, hdr + meta_size, hdr + min(meta_size + copy_size,
                                                            len(blob) - hdr))
        entries = _entries(blob, hdr + 48, hdr + min(meta_size, len(blob) - hdr))

        self.description = None
        self._fvek_entry = None
        for e in entries:
            if e["entry_type"] == ENTRY_VMK and e["value_type"] == VALUE_VMK:
                self.protectors.append(self._parse_vmk(e["data"]))
            elif e["entry_type"] == ENTRY_FVEK and e["value_type"] == VALUE_AES_CCM:
                self._fvek_entry = e["data"]
            elif e["entry_type"] == ENTRY_DESCRIPTION:
                self.description = e["data"].decode("utf-16-le", "replace") \
                    .rstrip("\x00")
            elif e["entry_type"] == ENTRY_VOLUME_HEADER and \
                    e["value_type"] == VALUE_OFFSET_SIZE and len(e["data"]) >= 16:
                vo, vs = struct.unpack_from("<QQ", e["data"], 0)
                self.volume_header = {"offset": vo, "size": vs}
        return True

    def _parse_vmk(self, data):
        guid = _guid(data[0:16])
        changed = _filetime(struct.unpack_from("<Q", data, 16)[0])
        ptype = struct.unpack_from("<H", data, 26)[0]
        return Protector(guid, changed, ptype, _entries(data, 28, len(data)))

    def info(self):
        usable = [p for p in self.protectors if p.usable]
        return {
            "type": "bitlocker",
            "valid": self.valid,
            "generation": getattr(self, "generation", None),
            "volume_guid": str(getattr(self, "volume_guid", "")) or None,
            "encryption": self.method_name,
            "mode": self.mode,
            "key_bits": (self.key_bytes or 0) * 8,
            "created": getattr(self, "created", None),
            "description": getattr(self, "description", None),
            "sector_size": getattr(self, "sector_size", 512),
            "protectors": [p.info() for p in self.protectors],
            "recoverable": bool(usable),
            "accepts": sorted({p.kind for p in usable}),
            "findings": self.findings + self._advice(),
        }

    @property
    def unlocked(self):
        return self.fvek is not None

    def unlock(self, secret, kind=None, progress=None, bek_key=None):
        if not self.valid:
            return {"unlocked": False, "reason": _t("bitlocker.usable_bitlocker_metadata")}
        if self.mode is None:
            return {"unlocked": False,
                    "reason": _t("bitlocker.encryption_method_x_x") % self.method}
        secret = (secret or "").strip()
        has_free = any(p.usable and p.kind == "none" for p in self.protectors)
        if not secret and not bek_key and not has_free:
            return {"unlocked": False, "reason": _t("bitlocker.password_key_supplied")}

        looks_recovery = _is_recovery_format(secret) if secret else False
        tried = []
        for p in self.protectors:
            if not p.usable or p.kind == "tpm":
                continue
            if kind and p.kind != kind:
                continue
            if p.kind == "recovery":
                if not secret or not looks_recovery:
                    continue
            elif p.kind == "password":
                if not secret or looks_recovery:
                    continue
            elif p.kind == "keyfile":
                if not bek_key:
                    continue
            tried.append(p.name)
            try:
                vmk = self._unwrap_vmk(p, secret, progress, bek_key=bek_key)
            except ccm.MacMismatch:
                continue
            except Exception as exc:
                self.findings.append("%s: %s" % (p.name, exc))
                continue
            if vmk is None:
                continue
            try:
                fvek = self._unwrap_fvek(vmk)
            except ccm.MacMismatch:
                return {"unlocked": False,
                        "reason": _t("bitlocker.opened_volume_master_key") % p.name}
            self.fvek = fvek
            check = self.verify()
            return {"unlocked": True, "protector": p.name,
                    "protector_guid": str(p.guid),
                    "encryption": self.method_name,
                    "verified_filesystem": check.get("filesystem"),
                    "verified": check.get("ok", False),
                    "reason": None if check.get("ok") else
                    "The key verified cryptographically but the decrypted "
                    "volume header carries no filesystem signature."}

        if not tried:
            return {"unlocked": False,
                    "reason": _t("bitlocker.nothing_volume_accepts_kind")
                              % ", ".join(p.name for p in self.protectors)}
        return {"unlocked": False,
                "reason": _t("bitlocker.incorrect") % (" or ".join(tried).lower())}

    def _unwrap_vmk(self, protector, secret, progress=None, bek_key=None):
        if protector.kind == "none":
            return self._unwrap_clear_vmk(protector)

        salt = None
        outer, nested = [], []
        for e in protector.entries:
            if e["value_type"] == VALUE_AES_CCM:
                outer.append(e["data"])
            elif e["value_type"] == VALUE_STRETCH_KEY and len(e["data"]) >= 20:
                salt = e["data"][4:20]
                nested += [n["data"] for n in
                           _entries(e["data"], 20, len(e["data"]))
                           if n["value_type"] == VALUE_AES_CCM]
        candidates = outer + nested
        if salt is None or not candidates:
            return None

        if protector.kind == "recovery":
            digits = _recovery_digits(secret)
            if digits is None:
                return None
            initial = hashlib.sha256(digits).digest()
        elif protector.kind == "keyfile":
            if not bek_key:
                return None
            initial = bek_key
        else:
            initial = hashlib.sha256(
                hashlib.sha256(secret.encode("utf-16-le")).digest()).digest()

        key = _stretch(initial, salt, progress)
        for blob in candidates:
            try:
                return _ccm_open(key, blob)
            except ccm.MacMismatch:
                continue
            except Unsupported:
                continue
        return None

    @staticmethod
    def _unwrap_clear_vmk(protector):
        """A clear-key protector's own entries hold the unwrapping key
        directly (a Key (0x0001) entry -- a 4-byte encryption-method field
        then the raw key) alongside the AES-CCM-wrapped VMK; unlike every
        other protector kind, there's no stretch key or salt at all."""
        raw_key = None
        candidates = []
        for e in protector.entries:
            if e["value_type"] == VALUE_KEY and len(e["data"]) > 4:
                raw_key = e["data"][4:]
            elif e["value_type"] == VALUE_AES_CCM:
                candidates.append(e["data"])
        if raw_key is None or not candidates:
            return None
        for blob in candidates:
            try:
                return _ccm_open(raw_key, blob)
            except ccm.MacMismatch:
                continue
            except Unsupported:
                continue
        return None

    def _unwrap_fvek(self, vmk):
        if not self._fvek_entry:
            raise Unsupported(_t("bitlocker.encryption_key_entry_metadata"))
        return _ccm_open(vmk, self._fvek_entry)

    def _keys(self):
        n = self.key_bytes
        if self.mode == "xts":
            return aes.AES(self.fvek[:n]), aes.AES(self.fvek[n:n * 2])
        return aes.AES(self.fvek[:n]), None

    def decrypt_sector(self, offset, data):
        k1, k2 = self._cached_keys()
        if self.mode == "xts":
            return aes.xts_decrypt(k1, k2, offset // self.sector_size, data,
                                   sector_size=self.sector_size)
        iv = k1.encrypt_block(struct.pack("<Q", offset) + b"\x00" * 8)
        plain = aes.cbc_decrypt(k1, iv, data)
        if self.mode == "cbc-diffuser":
            plain = diffuser_decrypt(plain, self.tweak_key, offset,
                                     self.sector_size)
        return plain

    def _cached_keys(self):
        if getattr(self, "_kc", None) is None:
            self._kc = self._keys()
        return self._kc

    def verify(self):
        if not self.fvek:
            return {"ok": False, "filesystem": None}
        head = self.read(0, 512)
        name = None
        if head[3:11] == b"NTFS    ":
            name = "NTFS"
        elif head[3:11] == b"EXFAT   ":
            name = "exFAT"
        elif head[54:62] in (b"FAT12   ", b"FAT16   "):
            name = head[54:62].decode().strip()
        elif head[82:90] == b"FAT32   ":
            name = "FAT32"
        ok = bool(name) and head[510:512] == b"\x55\xAA"
        return {"ok": ok, "filesystem": name}

    def read(self, offset, length):
        if not self.fvek:
            raise Unsupported(_t("bitlocker.volume_locked"))
        ss = self.sector_size
        out = bytearray()
        start = offset - (offset % ss)
        end = offset + length
        pos = start
        vh = self.volume_header or {}
        vh_off, vh_size = vh.get("offset", 0), vh.get("size", 0)
        while pos < end:
            src_off = pos
            if vh_size and pos < vh_size:
                src_off = vh_off + pos
            raw = self.source.read_at(src_off, ss)
            if len(raw) < ss:
                break
            out += self.decrypt_sector(src_off, raw)
            pos += ss
        head = offset - start
        return bytes(out[head:head + length])

    def _advice(self):
        if not self.protectors:
            return ["No key protectors were found in the metadata."]
        if any(p.kind == "none" for p in self.protectors):
            return ["A clear-key protector is present: this volume can be "
                    "opened with no secret at all. That normally means "
                    "encryption was suspended or still in progress."]
        if not any(p.usable for p in self.protectors):
            kinds = ", ".join(sorted({p.name for p in self.protectors}))
            return ["Every protector on this volume (%s) is bound to hardware "
                    "that did not come with the image. No password or recovery "
                    "key will open it." % kinds]
        return []
