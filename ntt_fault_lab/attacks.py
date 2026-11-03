"""
End-to-end attacks of Ravi et al. (TCHES 2023) on the ML-KEM IND-CPA PKE,
reproduced in simulation with the faulted NTT:

  * key recovery   : fault NTT(s) in KeyGen  -> recover the device secret key
  * message recovery: fault NTT(r) in Encrypt -> recover the plaintext

Success criteria are *functional*, not proxies:
  key recovery     : recovered secret key decrypts fresh ciphertexts correctly
  message recovery : recovered message equals the encrypted message
"""
import itertools
import time
import numpy as np
from kyber import (Q, N, ntt, intt, basemul, keygen, encrypt, decrypt,
                   decompress, compress, centered, PARAMS)


def xshift(a):
    """Multiply by X in Z_q[X]/(X^256+1)."""
    r = np.roll(a, 1, axis=-1)
    r[..., 0] = (-r[..., 0]) % Q
    return r % Q


def candidates(k, eta):
    vals = np.arange(-eta, eta + 1)
    return np.array(list(itertools.product(vals, repeat=2 * k)), dtype=np.int64)


def _search(target_rows, basis_rows, k, eta, chunk=50000):
    """Return (best candidate, best score).  target_rows: (k,256);
    basis_rows: (k, 2k, 256).  score = max_i max_coeff |target_i - C.basis_i|."""
    C = candidates(k, eta)
    best, best_score = None, None
    for s in range(0, len(C), chunk):
        Cc = C[s:s + chunk]
        score = np.zeros(len(Cc), dtype=np.int64)
        for i in range(k):
            R = centered(target_rows[i][None, :] - Cc @ basis_rows[i])
            score = np.maximum(score, np.abs(R).max(axis=1))
        j = int(np.argmin(score))
        if best_score is None or score[j] < best_score:
            best, best_score = Cc[j], int(score[j])
    return best, best_score


def faulty_ntt_factory(table):
    return lambda x: ntt(x, table)


def key_recovery_trial(rng, param="ML-KEM-768", fault_s=None, fault_e=None,
                       n_check=4):
    """One key-recovery experiment.  fault_s / fault_e: faulted twiddle tables
    (1-D, 128) applied to NTT(s) / NTT(e), or None for genuine."""
    k, eta1, eta2, du, dv = PARAMS[param]
    ntt_s = faulty_ntt_factory(fault_s) if fault_s is not None else None
    ntt_e = faulty_ntt_factory(fault_e) if fault_e is not None else None
    pk, shat_dev, s, e = keygen(rng, k, eta1, ntt_s=ntt_s, ntt_e=ntt_e)
    Ahat, that = pk
    t = intt(that)
    A = np.array([[intt(Ahat[i, j]) for j in range(k)] for i in range(k)])
    basis = np.array([[v for j in range(k) for v in (A[i, j], xshift(A[i, j]))]
                      for i in range(k)])
    t0 = time.time()
    cand, score = _search(t, basis, k, eta1)
    dt = time.time() - t0
    # build the recovered secret key  sk' = NTT(a + bX)
    s_rec = np.zeros((k, N), dtype=np.int64)
    s_rec[:, 0] = cand[0::2]
    s_rec[:, 1] = cand[1::2]
    shat_rec = ntt(s_rec)
    # functional check: decrypt fresh ciphertexts sent to the (faulted) device
    ok = True
    for _ in range(n_check):
        m = rng.integers(0, 2, N)
        ct, _ = encrypt(rng, pk, m, k, eta1, eta2, du, dv)
        ok &= np.array_equal(decrypt(shat_rec, ct, k, du, dv), m)
    # sanity: does the faulted device itself still decrypt correctly?
    m = rng.integers(0, 2, N)
    ct, _ = encrypt(rng, pk, m, k, eta1, eta2, du, dv)
    device_ok = np.array_equal(decrypt(shat_dev, ct, k, du, dv), m)
    return bool(ok), score, dt, bool(device_ok)


def message_recovery_trial(rng, param="ML-KEM-768", fault_r=None):
    k, eta1, eta2, du, dv = PARAMS[param]
    pk, shat, s, e = keygen(rng, k, eta1)
    Ahat, that = pk
    m = rng.integers(0, 2, N)
    ntt_r = faulty_ntt_factory(fault_r) if fault_r is not None else None
    (c1, c2), r = encrypt(rng, pk, m, k, eta1, eta2, du, dv, ntt_r=ntt_r)
    device_ok = np.array_equal(decrypt(shat, (c1, c2), k, du, dv), m)
    u = decompress(c1, du)
    v = decompress(c2, dv)
    AT = np.array([[intt(Ahat[j, i]) for j in range(k)] for i in range(k)])
    basis = np.array([[vv for j in range(k) for vv in (AT[i, j], xshift(AT[i, j]))]
                      for i in range(k)])
    t0 = time.time()
    cand, score = _search(u, basis, k, eta1)
    dt = time.time() - t0
    r_rec = np.zeros((k, N), dtype=np.int64)
    r_rec[:, 0] = cand[0::2]
    r_rec[:, 1] = cand[1::2]
    t = intt(that)
    acc = np.zeros(N, dtype=np.int64)
    for j in range(k):
        acc = (acc + basemul(that[j], ntt(r_rec[j]))) % Q
    m_rec = compress((v - intt(acc)) % Q, 1)
    return bool(np.array_equal(m_rec, m)), score, dt, bool(device_ok)
