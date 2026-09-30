"""Split a disk image into the member images of a RAID 0, 1 or 5 set.

Written forwards (walk the rows, place each chunk) where engine.raid maps
backwards (from an array offset to a member), and with the parity placement
spelled out per layout, so the two do not share a mistake. The placement
tables the tests check against are in the md documentation's diagrams."""

# For each layout: which member holds parity in a row, and the members that
# hold data chunks 0, 1, 2, ... of that row, in order.
def parity_and_data(layout, row, n):
    if layout == "left-symmetric":
        pd = n - 1 - row % n
        order = [(pd + 1 + k) % n for k in range(n - 1)]
    elif layout == "right-symmetric":
        pd = row % n
        order = [(pd + 1 + k) % n for k in range(n - 1)]
    elif layout == "left-asymmetric":
        pd = n - 1 - row % n
        order = [d for d in range(n) if d != pd]
    elif layout == "right-asymmetric":
        pd = row % n
        order = [d for d in range(n) if d != pd]
    else:
        raise ValueError(layout)
    return pd, order


def _xor(chunks):
    out = bytearray(len(chunks[0]))
    for c in chunks:
        for i, b in enumerate(c):
            out[i] ^= b
    return bytes(out)


def split(virtual, level, n, chunk=None, layout="left-symmetric", offset=0,
          fill=b"\xEE"):
    """Member images (bytes) for `virtual`. `offset` bytes of `fill` come
    before the data on every member, as a superblock or a controller's
    reserved area would."""
    if level == 1:
        return [fill * offset + virtual for _ in range(n)]
    data_per_row = n if level == 0 else n - 1
    row_bytes = chunk * data_per_row
    virtual = virtual + bytes((-len(virtual)) % row_bytes)
    members = [bytearray(fill * offset) for _ in range(n)]
    for row in range(len(virtual) // row_bytes):
        pieces = [virtual[row * row_bytes + k * chunk:
                          row * row_bytes + (k + 1) * chunk]
                  for k in range(data_per_row)]
        if level == 0:
            for disk in range(n):
                members[disk] += pieces[disk]
        else:
            pd, order = parity_and_data(layout, row, n)
            for k, disk in enumerate(order):
                members[disk] += pieces[k]
            members[pd] += _xor(pieces)
    return [bytes(m) for m in members]
