"""Build a small multi-partition GPT disk, with names, types and gaps, for
the volume-layout tests. Sparse and tiny: partitions start a few sectors in
rather than at the 1 MiB mark real tools use."""

import binascii
import struct
import uuid

import imagebuild_ntfs as ntfs

SECTOR = 512
BASIC = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"
LINUX = "0fc63daf-8483-4772-8e79-3d69d8477de4"
EFI = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
HFS = "48465300-0000-11aa-aa11-00306543ecac"
FIRST_USABLE = 34


def build(parts, total_sectors):
    """`parts` is [(first lba, sector count, type guid, name, content)];
    the backup array and header take the last 33 sectors."""
    disk = bytearray(total_sectors * SECTOR)
    last_lba = total_sectors - 1
    mbr = bytearray(SECTOR)
    mbr[446:462] = struct.pack("<B3sB3sII", 0, b"\x00\x02\x00", 0xEE,
                               b"\xFF\xFF\xFF", 1, min(last_lba, 0xFFFFFFFF))
    mbr[510:512] = b"\x55\xAA"
    disk[:SECTOR] = mbr
    array = bytearray(ntfs.GPT_ENTRIES * ntfs.GPT_ENTRY_SIZE)
    for i, (first, count, kind, name, content) in enumerate(parts):
        e = bytearray(ntfs.GPT_ENTRY_SIZE)
        e[0:16] = uuid.UUID(kind).bytes_le
        e[16:32] = uuid.UUID(int=0x1000 + i).bytes_le
        struct.pack_into("<QQQ", e, 32, first, first + count - 1, 0)
        raw = name.encode("utf-16-le")[:72]
        e[56:56 + len(raw)] = raw
        array[i * ntfs.GPT_ENTRY_SIZE:(i + 1) * ntfs.GPT_ENTRY_SIZE] = e
        if content:
            disk[first * SECTOR:first * SECTOR + len(content)] = content
    array = bytes(array)
    crc = binascii.crc32(array) & 0xFFFFFFFF
    guid = uuid.UUID(int=0xA1).bytes_le
    last_usable = last_lba - 1 - ntfs.GPT_ARRAY_SECTORS
    disk[SECTOR:2 * SECTOR] = ntfs._gpt_header(
        1, last_lba, 2, FIRST_USABLE, last_usable, guid, crc)
    disk[2 * SECTOR:2 * SECTOR + len(array)] = array
    backup = last_lba - ntfs.GPT_ARRAY_SECTORS
    disk[backup * SECTOR:backup * SECTOR + len(array)] = array
    disk[last_lba * SECTOR:] = ntfs._gpt_header(
        last_lba, 1, backup, FIRST_USABLE, last_usable, guid, crc)
    return bytes(disk), last_usable
