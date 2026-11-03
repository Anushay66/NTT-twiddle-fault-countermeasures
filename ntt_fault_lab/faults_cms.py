"""
Fault outcomes (Definition 2 of the paper, extended) and the three
countermeasures C1, C2, C3 (RATS), vectorised over a batch of trials.
"""
import hashlib
import hmac
import numpy as np
from kyber import Q, N, GENUINE_TABLE

N_ROOT = 256          # order of the root of unity: genuine twiddles satisfy t^256 = 1
USED = np.arange(1, 128)  # indices of the twiddle table actually consumed by the NTT


# ------------------------------------------------------------------ faults
def fault_tables(kind, batch, rng, c=None, delta=1):
    """Return a (batch, 128) array of faulted tables T* (abstract Z_q model).

    kind:
      'none'      genuine table
      'zero'      T* = (0,...,0)                       [Ravi et al., all attacks]
      'stuck'     T* = (c,...,c); c fixed (int) or 'generic' = uniform over
                  Z_q \\ {0, 1, q-1} drawn independently per trial
      'random'    T* uniform over Z_q^128 (random redirection)
      'shifted'   pointer off by `delta` entries: T*_i = T_{i+delta}; the
                  entries read past the end of the table are random data
                  (models a low-order address-bit flip)
    """
    if kind == "none":
        return np.tile(GENUINE_TABLE, (batch, 1))
    if kind == "zero":
        return np.zeros((batch, 128), dtype=np.int64)
    if kind == "stuck":
        if c == "generic":
            cs = rng.integers(2, Q - 1, size=batch)  # excludes 0, 1, q-1
            return np.repeat(cs[:, None], 128, axis=1).astype(np.int64)
        return np.full((batch, 128), int(c) % Q, dtype=np.int64)
    if kind == "random":
        return rng.integers(0, Q, size=(batch, 128), dtype=np.int64)
    if kind == "shifted":
        t = np.empty((batch, 128), dtype=np.int64)
        t[:, : 128 - delta] = GENUINE_TABLE[delta:]
        t[:, 128 - delta:] = rng.integers(0, Q, size=(batch, delta))
        return t
    raise ValueError(kind)


# ------------------------------------------------------------------ C1
def c1_detect(tables, t, rng, used=USED):
    """C1 (Algorithm 1): sample t distinct consumed indices, abort if an entry is
    zero or fails x^256 == 1 (mod q).  Returns boolean array (batch,)."""
    batch = tables.shape[0]
    idx = np.argsort(rng.random((batch, len(used))), axis=1)[:, :t]
    samp = tables[np.arange(batch)[:, None], used[idx]] % Q
    # x^256 by 8 squarings
    x = samp.copy()
    for _ in range(8):
        x = (x * x) % Q
    bad = (samp == 0) | (x != 1)
    return bad.any(axis=1)


# ------------------------------------------------------------------ C2
def entropy_rows(out):
    """Empirical Shannon entropy (bits) of each row of `out` (batch, n)."""
    out = np.asarray(out) % Q
    batch, n = out.shape
    keys = np.arange(batch)[:, None] * Q + out
    uniq, counts = np.unique(keys.ravel(), return_counts=True)
    rows = uniq // Q
    p = counts / n
    return np.bincount(rows, weights=-p * np.log2(p), minlength=batch)


def distinct_rows(out):
    out = np.sort(np.asarray(out) % Q, axis=1)
    return 1 + (np.diff(out, axis=1) != 0).sum(axis=1)


def c2_detect(out, tau=6.0):
    """C2 (Algorithm 2): abort if empirical entropy < tau."""
    return entropy_rows(out) < tau


def c2_proxy_detect(out, dmin=128):
    """Embedded-friendly proxy: abort if fewer than dmin distinct values."""
    return distinct_rows(out) < dmin


# ------------------------------------------------------------------ C3 (RATS)
def table_bytes(table):
    return np.asarray(table, dtype=np.int64).astype("<u2").tobytes()


class RATS:
    """Randomized Authenticated Twiddle Storage, option (a) of the revision:
    m byte-identical copies, ONE tag over the table contents (no index binding).
    The tag authenticates *what was fetched*; which copy was selected only
    matters for physical targeting (see paper, Sec. IV-C)."""

    def __init__(self, m=4, mode="keyless", key=b"device-key-0123456789abcdef", h_bits=256):
        self.m = m
        self.mode = mode
        self.key = key
        self.h_bits = h_bits
        self.tag = self._tag(GENUINE_TABLE)

    def _tag(self, table):
        b = table_bytes(table)
        if self.mode == "keyless":
            d = hashlib.sha256(b).digest()
        else:
            d = hmac.new(self.key, b, hashlib.sha256).digest()
        nbytes = (self.h_bits + 7) // 8
        v = int.from_bytes(d[:nbytes], "big") >> (8 * nbytes - self.h_bits)
        return v

    def detect(self, fetched_tables, rng=None):
        """fetched_tables: (batch,128) contents actually read through the
        (possibly faulted) pointer.  Selection of the copy index is irrelevant for
        the integrity decision because all copies are identical."""
        return np.array([self._tag(t) != self.tag for t in fetched_tables])


# ------------------------------------------------------------------ helpers
def low_entropy(out, max_support=64):
    """Low-entropy indicator used in v1 as 'attack success' proxy (kept only as
    a descriptive statistic; real attack success comes from attacks.py)."""
    return distinct_rows(out) <= max_support
