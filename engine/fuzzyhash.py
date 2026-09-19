"""Context-triggered piecewise hashing (CTPH) -- the algorithm behind
ssdeep. Produces the same "blocksize:sig1:sig2" digests ssdeep does, and
scores two digests for similarity the same way, so results here can be
checked against real ssdeep/ppdeep output. Reimplemented from the published
spamsum/ssdeep algorithm (Andrew Tridgell's spamsum, Jesse Kornblum's
ssdeep), not ported from any existing implementation.

Unlike md5/sha1/sha256, this digest is a fuzzy fingerprint: files that
differ only in a few places produce digests that partially match, and
`compare()` returns how alike two digests are (0-100) rather than an
exact/no-match test.
"""

MIN_BLOCK_SIZE = 3
SPAMSUM_LENGTH = 64
_ROLL_WINDOW = 7
_HASH_INIT = 0x27

_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

# Fixed permutation of 0-63 used by spamsum's block hash. A public constant
# of the algorithm (like a CRC table), not tunable -- reproducing it exactly
# is what makes the output interoperable with real ssdeep.
_F_TABLE = (
    0x00, 0x13, 0x26, 0x39, 0x0c, 0x1f, 0x32, 0x05,
    0x18, 0x2b, 0x3e, 0x11, 0x24, 0x37, 0x0a, 0x1d,
    0x30, 0x03, 0x16, 0x29, 0x3c, 0x0f, 0x22, 0x35,
    0x08, 0x1b, 0x2e, 0x01, 0x14, 0x27, 0x3a, 0x0d,
    0x20, 0x33, 0x06, 0x19, 0x2c, 0x3f, 0x12, 0x25,
    0x38, 0x0b, 0x1e, 0x31, 0x04, 0x17, 0x2a, 0x3d,
    0x10, 0x23, 0x36, 0x09, 0x1c, 0x2f, 0x02, 0x15,
    0x28, 0x3b, 0x0e, 0x21, 0x34, 0x07, 0x1a, 0x2d,
)


def _block_hash_next(h, b):
    return _F_TABLE[h] ^ (b & 0x3F)


class _RollingHash:
    """A 7-byte rolling checksum; low when the last few bytes are similar
    to a few bytes before them, used only to pick trigger points."""

    __slots__ = ("_window", "_h1", "_h2", "_h3", "_pos")

    def __init__(self):
        self._window = [0] * _ROLL_WINDOW
        self._h1 = self._h2 = self._h3 = 0
        self._pos = 0

    def update(self, b):
        slot = self._pos % _ROLL_WINDOW
        self._h2 = self._h2 - self._h1 + _ROLL_WINDOW * b
        self._h1 = self._h1 + b - self._window[slot]
        self._window[slot] = b
        self._pos += 1
        self._h3 = ((self._h3 << 5) & 0xFFFFFFFF) ^ b
        return (self._h1 + self._h2 + self._h3) & 0xFFFFFFFF


def _initial_block_size(length):
    bs = MIN_BLOCK_SIZE
    while bs * SPAMSUM_LENGTH < length:
        bs *= 2
    return bs


def _piecewise_pass(data, block_size):
    roll = _RollingHash()
    h1 = h2 = _HASH_INIT
    sig1, sig2 = [], []
    last1 = last2 = ""
    rh = 0
    for b in data:
        h1 = _block_hash_next(h1, b)
        h2 = _block_hash_next(h2, b)
        rh = roll.update(b)
        if rh % block_size == block_size - 1:
            last1 = _B64[h1]
            if len(sig1) < SPAMSUM_LENGTH - 1:
                sig1.append(_B64[h1])
                h1 = _HASH_INIT
                last1 = ""
            if rh % (block_size * 2) == block_size * 2 - 1:
                last2 = _B64[h2]
                if len(sig2) < SPAMSUM_LENGTH // 2 - 1:
                    sig2.append(_B64[h2])
                    h2 = _HASH_INIT
                    last2 = ""
    # The trailing block hash is not yet part of sig1/sig2 -- whether it
    # gets appended is decided by the caller, since the length that decides
    # a block-size retry is measured *before* this last character lands.
    tail1 = _B64[h1] if rh != 0 else last1
    tail2 = _B64[h2] if rh != 0 else last2
    return "".join(sig1), "".join(sig2), tail1, tail2


def hash_bytes(data):
    """The ssdeep-compatible fuzzy hash of `data`, as "blocksize:sig1:sig2"."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray, not %r" % type(data))
    block_size = _initial_block_size(len(data))
    while True:
        sig1, sig2, tail1, tail2 = _piecewise_pass(data, block_size)
        if block_size > MIN_BLOCK_SIZE and len(sig1) < SPAMSUM_LENGTH // 2:
            block_size //= 2
            continue
        return "%d:%s:%s" % (block_size, sig1 + tail1, sig2 + tail2)


def _levenshtein(s, t):
    if s == t:
        return 0
    if not s:
        return len(t)
    if not t:
        return len(s)
    prev = list(range(len(t) + 1))
    for i, sc in enumerate(s):
        cur = [i + 1] + [0] * len(t)
        for j, tc in enumerate(t):
            cost = 0 if sc == tc else 1
            cur[j + 1] = min(cur[j] + 1, prev[j + 1] + 1, prev[j] + cost)
        prev = cur
    return prev[len(t)]


def _has_common_substring(s1, s2, min_len=_ROLL_WINDOW):
    for i in range(len(s1)):
        for j in range(len(s2)):
            k = 0
            while i + k < len(s1) and j + k < len(s2) and s1[i + k] == s2[j + k]:
                k += 1
                if k >= min_len:
                    return True
    return False


def _strip_runs(s):
    """Collapses runs of 4+ identical characters down to 3, so that mere
    repetition (long runs of the same byte, which pad the signature with
    the same emitted character) doesn't dominate the edit distance."""
    if len(s) <= 3:
        return s
    out = list(s[:3])
    for i in range(3, len(s)):
        if not (s[i] == s[i - 1] == s[i - 2] == s[i - 3]):
            out.append(s[i])
    return "".join(out)


def _score_strings(s1, s2, block_size):
    if not _has_common_substring(s1, s2):
        return 0
    score = _levenshtein(s1, s2)
    score = (score * SPAMSUM_LENGTH) // (len(s1) + len(s2))
    score = (100 * score) // SPAMSUM_LENGTH
    score = 100 - score
    cap = block_size // MIN_BLOCK_SIZE * min(len(s1), len(s2))
    return min(score, cap)


def compare(hash1, hash2):
    """Similarity of two fuzzy hashes, 0 (unrelated) to 100 (identical).
    Two hashes only compare at all if their block sizes match or one is
    double the other -- ssdeep hashes at unrelated block sizes carry no
    comparable signal, by design."""
    if not (isinstance(hash1, str) and isinstance(hash2, str)):
        raise TypeError("hashes must be strings")
    try:
        bs1_s, s1_1, s1_2 = hash1.split(":")
        bs2_s, s2_1, s2_2 = hash2.split(":")
        bs1, bs2 = int(bs1_s), int(bs2_s)
    except ValueError:
        raise ValueError("invalid fuzzy hash format") from None

    if bs1 != bs2 and bs1 != bs2 * 2 and bs2 != bs1 * 2:
        return 0

    s1_1, s1_2 = _strip_runs(s1_1), _strip_runs(s1_2)
    s2_1, s2_2 = _strip_runs(s2_1), _strip_runs(s2_2)

    if bs1 == bs2 and s1_1 == s2_1:
        return 100
    if bs1 == bs2:
        return max(_score_strings(s1_1, s2_1, bs1),
                    _score_strings(s1_2, s2_2, bs2 * 2))
    if bs1 == bs2 * 2:
        return _score_strings(s1_1, s2_2, bs1)
    return _score_strings(s1_2, s2_1, bs2)
