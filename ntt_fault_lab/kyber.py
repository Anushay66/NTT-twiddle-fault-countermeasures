"""
Behavioural model of the ML-KEM (Kyber) incomplete NTT and the IND-CPA PKE,
vectorised with numpy so that tens of thousands of Monte Carlo trials run in
seconds.  All arithmetic is exact mod q (no Montgomery/Plantard scaling); the
twiddle table is an explicit argument so that pointer-redirection faults can be
modelled by substituting the table.

Conventions follow FIPS 203 / the Kyber reference implementation:
  * q = 3329, n = 256, zeta = 17 (primitive 256-th root of unity)
  * forward NTT: 7 Cooley-Tukey layers, len = 128 ... 2, zetas[k] = 17^brv7(k)
  * NTT domain = 128 pairs (a_{2i}, a_{2i+1}) representing a mod (X^2 - gamma_i)
"""
import numpy as np

Q = 3329
N = 256
ZETA = 17

PARAMS = {  # name: (k, eta1, eta2, du, dv)
    "ML-KEM-512": (2, 3, 2, 10, 4),
    "ML-KEM-768": (3, 2, 2, 10, 4),
    "ML-KEM-1024": (4, 2, 2, 11, 5),
}


def brv7(x):
    return int(format(x, "07b")[::-1], 2)


GENUINE_TABLE = np.array([pow(ZETA, brv7(k), Q) for k in range(128)], dtype=np.int64)
# gamma_i used by base multiplication: zeta^(2 brv7(i) + 1)
GAMMAS = np.array([pow(ZETA, 2 * brv7(i) + 1, Q) for i in range(128)], dtype=np.int64)


def ntt(a, table=None):
    """Forward NTT of a batch of polynomials.

    a     : int array (..., 256), any integer representatives
    table : None (genuine), 1-D array (128,) shared by the batch,
            or 2-D array (batch, 128) with one (possibly faulted) table per row.
    """
    r = np.array(a, dtype=np.int64) % Q
    if r.ndim == 1:
        r = r[None, :]
        squeeze = True
    else:
        squeeze = False
    if table is None:
        table = GENUINE_TABLE
    table = np.asarray(table, dtype=np.int64) % Q
    per_row = table.ndim == 2
    k = 1
    length = 128
    while length >= 2:
        for start in range(0, N, 2 * length):
            z = table[:, k][:, None] if per_row else table[k]
            k += 1
            hi = r[:, start + length:start + 2 * length]
            lo = r[:, start:start + length]
            t = (z * hi) % Q
            r[:, start + length:start + 2 * length] = (lo - t) % Q
            r[:, start:start + length] = (lo + t) % Q
        length //= 2
    return r[0] if squeeze else r


_INV_TABLE = None


def intt(ahat):
    """Inverse NTT (genuine), batch-aware, output in [0, q)."""
    r = np.array(ahat, dtype=np.int64) % Q
    squeeze = r.ndim == 1
    if squeeze:
        r = r[None, :]
    k = 127
    length = 2
    while length <= 128:
        for start in range(0, N, 2 * length):
            z = int(GENUINE_TABLE[k])
            k -= 1
            lo = r[:, start:start + length].copy()
            hi = r[:, start + length:start + 2 * length]
            r[:, start:start + length] = (lo + hi) % Q
            r[:, start + length:start + 2 * length] = (z * (hi - lo)) % Q
        length *= 2
    r = (r * 3303) % Q  # 3303 = 128^{-1} mod q
    return r[0] if squeeze else r


def basemul(ahat, bhat):
    """Pointwise product in the NTT domain (128 degree-1 products mod X^2-gamma)."""
    a0, a1 = ahat[..., 0::2], ahat[..., 1::2]
    b0, b1 = bhat[..., 0::2], bhat[..., 1::2]
    c0 = (a0 * b0 + (a1 * b1 % Q) * GAMMAS) % Q
    c1 = (a0 * b1 + a1 * b0) % Q
    out = np.empty(np.broadcast(ahat, bhat).shape, dtype=np.int64)
    out[..., 0::2] = c0
    out[..., 1::2] = c1
    return out


def polymul_negacyclic(a, b):
    """Schoolbook multiplication in Z_q[X]/(X^256+1) (used only for tests)."""
    a = np.asarray(a, dtype=np.int64) % Q
    b = np.asarray(b, dtype=np.int64) % Q
    full = np.convolve(a, b)
    res = full[:N].copy()
    res[: len(full) - N] -= full[N:]
    return res % Q


def centered(x):
    x = np.asarray(x, dtype=np.int64) % Q
    return np.where(x > Q // 2, x - Q, x)


def cbd(rng, eta, shape):
    a = rng.integers(0, 2, size=shape + (eta,)).sum(-1)
    b = rng.integers(0, 2, size=shape + (eta,)).sum(-1)
    return (a - b).astype(np.int64)


def compress(x, d):
    x = np.asarray(x, dtype=np.int64) % Q
    return ((x * (1 << d) + Q // 2) // Q) % (1 << d)


def decompress(y, d):
    y = np.asarray(y, dtype=np.int64)
    return (y * Q + (1 << (d - 1))) >> d


# ---------------------------------------------------------------- IND-CPA PKE
def keygen(rng, k=3, eta1=2, ntt_s=None, ntt_e=None):
    """CPA key generation.  ntt_s / ntt_e: callables replacing NTT(s) / NTT(e)
    (used to inject the twiddle-pointer fault).  Returns pk=(Ahat,that), sk=shat
    plus the ground-truth s, e for evaluation."""
    ntt_s = ntt_s or ntt
    ntt_e = ntt_e or ntt
    Ahat = rng.integers(0, Q, size=(k, k, N), dtype=np.int64)
    s = cbd(rng, eta1, (k, N))
    e = cbd(rng, eta1, (k, N))
    shat = ntt_s(s)
    ehat = ntt_e(e)
    that = np.zeros((k, N), dtype=np.int64)
    for i in range(k):
        acc = np.zeros(N, dtype=np.int64)
        for j in range(k):
            acc = (acc + basemul(Ahat[i, j], shat[j])) % Q
        that[i] = (acc + ehat[i]) % Q
    return (Ahat, that), shat, s, e


def encrypt(rng, pk, m_bits, k=3, eta1=2, eta2=2, du=10, dv=4, ntt_r=None):
    ntt_r = ntt_r or ntt
    Ahat, that = pk
    r = cbd(rng, eta1, (k, N))
    e1 = cbd(rng, eta2, (k, N))
    e2 = cbd(rng, eta2, (N,))
    rhat = ntt_r(r)
    u = np.zeros((k, N), dtype=np.int64)
    for i in range(k):
        acc = np.zeros(N, dtype=np.int64)
        for j in range(k):
            acc = (acc + basemul(Ahat[j, i], rhat[j])) % Q  # A^T
        u[i] = (intt(acc) + e1[i]) % Q
    acc = np.zeros(N, dtype=np.int64)
    for j in range(k):
        acc = (acc + basemul(that[j], rhat[j])) % Q
    v = (intt(acc) + e2 + decompress(m_bits, 1)) % Q
    return (compress(u, du), compress(v, dv)), r


def decrypt(shat, ct, k=3, du=10, dv=4):
    c1, c2 = ct
    u = decompress(c1, du)
    v = decompress(c2, dv)
    acc = np.zeros(N, dtype=np.int64)
    for j in range(k):
        acc = (acc + basemul(shat[j], ntt(u[j]))) % Q
    return compress((v - intt(acc)) % Q, 1)


def self_test():
    rng = np.random.default_rng(1)
    a = rng.integers(0, Q, N)
    b = rng.integers(0, Q, N)
    assert np.array_equal(intt(ntt(a)), a % Q), "intt(ntt(a)) != a"
    assert np.array_equal(intt(basemul(ntt(a), ntt(b))), polymul_negacyclic(a, b)), "basemul"
    assert pow(ZETA, 256, Q) == 1 and pow(ZETA, 128, Q) == Q - 1
    k, eta1, eta2, du, dv = PARAMS["ML-KEM-768"]
    pk, shat, s, e = keygen(rng, k, eta1)
    m = rng.integers(0, 2, N)
    ct, _ = encrypt(rng, pk, m, k, eta1, eta2, du, dv)
    assert np.array_equal(decrypt(shat, ct, k, du, dv), m), "PKE decryption"
    # zero-fault structure: faulty NTT(x) == NTT(x0 + x1 X)
    x = cbd(rng, 2, (N,))
    f = ntt(x, np.zeros(128, dtype=np.int64))
    sparse = np.zeros(N, dtype=np.int64)
    sparse[:2] = x[:2]
    assert np.array_equal(f, ntt(sparse)), "zero-fault structure"
    return True


if __name__ == "__main__":
    print("self test:", self_test())
