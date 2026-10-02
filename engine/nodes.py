"""The handle a filesystem reader gives each entry it lists.

Every reader names an entry by one field of its own: the MFT record number
(NTFS), the inode (ext), the object ID (APFS, and logical evidence), the
catalog node ID (HFS+) or the first cluster (FAT and exFAT). Anything that
goes on to list a folder, open a file by handle, key a tag or a hash, or
cross-reference an entry has to pick whichever one is there. That choice was
once written out at each place that made it, and HFS+ was left out of most of
them: its folders were never descended into and nothing keyed on its entries
could be kept. It is made here, once."""

KEYS = ("mft", "inode", "oid", "cnid", "start_cluster")


def node_of(entry):
    """The entry's handle, or None if it has none."""
    for key in KEYS:
        value = entry.get(key)
        if value is not None:
            return value
    return None


def node_key(entry):
    """The handle as a string, for keying; None if the entry has none."""
    value = node_of(entry)
    return None if value is None else str(value)
