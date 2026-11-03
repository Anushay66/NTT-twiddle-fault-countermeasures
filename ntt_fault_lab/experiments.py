"""
All experiments reported in the revised paper.  Usage:

    python3 experiments.py all          # everything (~10-15 min on a laptop)
    python3 experiments.py main         # Table: detection / release rates
    python3 experiments.py sweep        # stuck-at sweep over all c in Z_q
    python3 experiments.py attacks      # end-to-end key / message recovery
    python3 experiments.py c1t          # C1 detection vs sample count t
    python3 experiments.py fp           # false-positive rates
    python3 experiments.py repr         # representation-aware C1 (pqm4 tables)
    python3 experiments.py effsecret    # effective secret behind a faulted key
    python3 experiments.py partial      # partial zeroization (fault during the transform)
    python3 experiments.py figs         # regenerate figures from results/

Every number in the revised paper is produced by this script with fixed seeds;
results are written to results/*.json, figures to figures/*.pdf.
"""
import json
import sys
import time
import numpy as np
from kyber import Q, N, ntt, cbd, GENUINE_TABLE, PARAMS, self_test
from faults_cms import (fault_tables, c1_detect, c2_detect, c2_proxy_detect,
                        entropy_rows, distinct_rows, low_entropy, RATS)
import attacks

RES = "results"
FIG = "figures"


import os
os.makedirs(RES, exist_ok=True)
os.makedirs(FIG, exist_ok=True)


def dump(name, obj):
    with open(f"{RES}/{name}.json", "w") as f:
        json.dump(obj, f, indent=2)
    print(f"  -> {RES}/{name}.json")


FAULTS = [
    ("zero", dict(kind="zero")),
    ("stuck c=+1", dict(kind="stuck", c=1)),
    ("stuck c=-1", dict(kind="stuck", c=Q - 1)),
    ("stuck generic c", dict(kind="stuck", c="generic")),
    ("random redirection", dict(kind="random")),
    ("shifted (delta=1)", dict(kind="shifted", delta=1)),
]


# ------------------------------------------------------------------ main table
def exp_main(trials=20000, eta=2, t=4, m=4, seed=20240601):
    rng = np.random.default_rng(seed)
    rats = RATS(m=m, mode="keyless")
    out = {"trials": trials, "eta": eta, "t": t, "m": m, "seed": seed, "rows": []}
    for name, kw in FAULTS:
        x = cbd(rng, eta, (trials, N))
        T = fault_tables(batch=trials, rng=rng, **kw)
        y = ntt(x, T)
        d1 = c1_detect(T, t, rng)
        d2 = c2_detect(y)
        d2p = c2_proxy_detect(y)
        d3 = rats.detect(T)
        dall = d1 | d2 | d3
        le = low_entropy(y)
        row = {
            "fault": name,
            "low_entropy_rate": float(le.mean()),
            "C1": float(d1.mean()), "C2": float(d2.mean()),
            "C2_proxy": float(d2p.mean()),
            "C2_proxy_agrees": float((d2 == d2p).mean()),
            "C3": float(d3.mean()), "C": float(dall.mean()),
        }
        out["rows"].append(row)
        print(f"  {name:22s} lowH={row['low_entropy_rate']:.4f}  C1={row['C1']:.5f} "
              f"C2={row['C2']:.5f} C3={row['C3']:.5f} C={row['C']:.5f}")
    dump("main", out)
    return out


# ------------------------------------------------------------------ stuck-at sweep
def exp_sweep(per_c=200, seed=42):
    rng = np.random.default_rng(seed)
    res = {"per_c": per_c, "seed": seed, "inputs": {}}
    cs = np.arange(Q)
    # C1 is deterministic for a stuck table: detect iff c == 0 or c^256 != 1
    c1 = np.array([(c == 0) or (pow(int(c), 256, Q) != 1) for c in cs])
    res["C1_detect_by_c"] = c1.astype(int).tolist()
    res["C1_undetected_count"] = int((~c1).sum())
    for label, gen in [("CBD eta=2", lambda b: cbd(rng, 2, (b, N))),
                       ("CBD eta=3", lambda b: cbd(rng, 3, (b, N))),
                       ("uniform", lambda b: rng.integers(0, Q, (b, N)))]:
        c2 = np.zeros(Q)
        meanH = np.zeros(Q)
        t0 = time.time()
        for c in cs:
            x = gen(per_c)
            y = ntt(x, np.full(128, c, dtype=np.int64))
            H = entropy_rows(y)
            c2[c] = (H < 6.0).mean()
            meanH[c] = H.mean()
        nz = cs != 0
        detected_cs = [int(c) for c in cs[nz] if c2[c] > 0]
        res["inputs"][label] = {
            "C2_detect_by_c": c2.tolist(), "meanH_by_c": meanH.tolist(),
            "C2_avg_over_nonzero_c": float(c2[nz].mean()),
            "nonzero_c_with_any_detection": detected_cs,
            "C2_rate_c_pm1": [float(c2[1]), float(c2[Q - 1])],
        }
        print(f"  {label:10s}: avg C2 over c!=0 = {c2[nz].mean():.5f}; "
              f"c with detection: {detected_cs[:10]}  ({time.time()-t0:.0f}s)")
    dump("sweep", res)
    return res


# ------------------------------------------------------------------ attacks
def exp_attacks(seed=7):
    rng = np.random.default_rng(seed)
    Z = np.zeros(128, dtype=np.int64)
    one = np.ones(128, dtype=np.int64)
    res = {"seed": seed, "key_recovery": [], "message_recovery": []}

    def stuck(c):
        return np.full(128, c % Q, dtype=np.int64)

    kr_cases = [
        ("ML-KEM-512", "zero on NTT(s)", Z, None, 100),
        ("ML-KEM-768", "zero on NTT(s)", Z, None, 100),
        ("ML-KEM-768", "zero on NTT(s), NTT(e)", Z, Z, 100),
        ("ML-KEM-1024", "zero on NTT(s)", Z, None, 10),
        ("ML-KEM-768", "no fault", None, None, 50),
        ("ML-KEM-768", "stuck c=+1", one, None, 50),
        ("ML-KEM-768", "stuck c=+1 on NTT(s), NTT(e)", one, one, 50),
        ("ML-KEM-768", "stuck c=-1", stuck(-1), None, 50),
        ("ML-KEM-768", "stuck c=17", stuck(17), None, 50),
        ("ML-KEM-768", "stuck generic c", "generic", None, 50),
        ("ML-KEM-768", "random redirection", "random", None, 50),
        ("ML-KEM-768", "shifted (delta=1)", "shifted", None, 50),
    ]
    for param, label, fs, fe, n in kr_cases:
        succ, dev, times = 0, 0, []
        for _ in range(n):
            s_tab = fs
            if isinstance(fs, str):
                kind = {"generic": "stuck", "random": "random", "shifted": "shifted"}[fs]
                kw = {"c": "generic"} if fs == "generic" else {}
                s_tab = fault_tables(kind, 1, rng, **kw)[0]
            ok, score, dt, dev_ok = attacks.key_recovery_trial(rng, param, s_tab, fe)
            succ += ok
            dev += dev_ok
            times.append(dt)
        row = {"param": param, "fault": label, "trials": n, "success": succ / n,
               "device_decrypts_correctly": dev / n, "search_time_s": float(np.mean(times))}
        res["key_recovery"].append(row)
        print(f"  KR {param:11s} {label:30s} success={succ/n:.2f}  device-ok={dev/n:.2f} "
              f"t={np.mean(times):.2f}s")

    mr_cases = [
        ("ML-KEM-768", "zero on NTT(r)", Z, 100),
        ("ML-KEM-512", "zero on NTT(r)", Z, 100),
        ("ML-KEM-768", "no fault", None, 50),
        ("ML-KEM-768", "stuck c=+1", one, 50),
        ("ML-KEM-768", "stuck generic c", "generic", 50),
        ("ML-KEM-768", "random redirection", "random", 50),
    ]
    for param, label, fr, n in mr_cases:
        succ, dev = 0, 0
        for _ in range(n):
            r_tab = fr
            if isinstance(fr, str):
                kind = {"generic": "stuck", "random": "random"}[fr]
                kw = {"c": "generic"} if fr == "generic" else {}
                r_tab = fault_tables(kind, 1, rng, **kw)[0]
            ok, score, dt, dev_ok = attacks.message_recovery_trial(rng, param, r_tab)
            succ += ok
            dev += dev_ok
        row = {"param": param, "fault": label, "trials": n, "success": succ / n,
               "receiver_decrypts_correctly": dev / n}
        res["message_recovery"].append(row)
        print(f"  MR {param:11s} {label:30s} success={succ/n:.2f}  receiver-ok={dev/n:.2f}")
    dump("attacks", res)
    return res


# ------------------------------------------------------------------ effective secret
def exp_effsecret(trials=2000, seed=11):
    """For a faulted NTT(s), the device stores shat* and the public key is
    consistent with the *effective* secret s' = INTT(shat*).  The zero fault
    gives s' = s0 + s1 X (small, sparse -> valid key, 5^2 search per poly);
    every invertible fault (c != 0, random, shifted) gives a non-small s'
    (decryption failure), i.e. a denial of service rather than a leak."""
    from kyber import intt, centered
    rng = np.random.default_rng(seed)
    rows = []
    cases = [("zero", dict(kind="zero")), ("stuck c=+1", dict(kind="stuck", c=1)),
             ("stuck c=-1", dict(kind="stuck", c=Q - 1)), ("stuck c=17", dict(kind="stuck", c=17)),
             ("stuck generic c", dict(kind="stuck", c="generic")),
             ("random redirection", dict(kind="random")), ("shifted (delta=1)", dict(kind="shifted"))]
    for name, kw in cases:
        x = cbd(rng, 2, (trials, N))
        T = fault_tables(batch=trials, rng=rng, **kw)
        sp = centered(intt(ntt(x, T)))
        linf = np.abs(sp).max(axis=1)
        nnz = (sp != 0).sum(axis=1)
        rows.append({"fault": name, "linf_mean": float(linf.mean()),
                     "nonzero_coeffs_mean": float(nnz.mean()),
                     "frac_small(|x|<=2)": float((np.abs(sp) <= 2).mean())})
        print(f"  {name:20s} ||s'||_inf mean={linf.mean():8.1f}  nonzero={nnz.mean():6.1f}  "
              f"frac |x|<=2: {(np.abs(sp) <= 2).mean():.3f}")
    dump("effsecret", {"trials": trials, "seed": seed, "rows": rows})


# ------------------------------------------------------------------ partial zeroization
def exp_partial(trials=2000, seed=13):
    """Zero twiddles from table index k0 on (the last layers), as produced by a
    fault on the twiddle-pointer register *during* the transform.  The effective
    secret then equals s on the 2*k0 positions {j : j mod (256/k0) in {0,1}} and
    is zero elsewhere (short, sparse, valid key): an LWE instance of dimension
    2*k0*k instead of 256*k."""
    from kyber import intt, centered, GENUINE_TABLE
    rng = np.random.default_rng(seed)
    rows = []
    for k0 in (1, 2, 4, 8, 16, 32, 64):
        T = GENUINE_TABLE.copy()
        T[k0:] = 0
        x = cbd(rng, 2, (trials, N))
        y = ntt(x, T)
        sp = centered(intt(y))
        # support: positions j with j mod (256/k0) in {0, 1}
        S = np.array([j for j in range(N) if j % (N // k0) in (0, 1)])
        rest = np.setdiff1d(np.arange(N), S)
        support_ok = bool(np.array_equal(sp[:, S], x[:, S])) and bool(np.all(sp[:, rest] == 0))
        d = distinct_rows(y)
        rows.append({"k0": k0, "free_coeffs_per_poly": 2 * k0, "distinct_mean": float(d.mean()),
                     "C2_detect": float((d < 128).mean()), "effective_secret_is_prefix_of_s": support_ok})
        print(f"  zero from k0={k0:3d}: s' = s on {2*k0:3d} known positions: {support_ok}; "
              f"distinct {d.mean():6.1f}; C2 detects {(d < 128).mean():.3f}")
    dump("partial", {"trials": trials, "seed": seed, "rows": rows})


# ------------------------------------------------------------------ C1 vs t
def exp_c1t(trials=20000, seed=42):
    rng = np.random.default_rng(seed)
    rows = []
    for t in range(1, 9):
        T = fault_tables("random", trials, rng)
        emp = float(c1_detect(T, t, rng).mean())
        # exact probability for uniform entries: an entry passes iff it is one of
        # the n roots (0 excluded) -> per-sample pass prob n/q
        theo = 1 - (256 / Q) ** t
        rows.append({"t": t, "empirical": emp, "theoretical": theo,
                     "stderr": float(np.sqrt(theo * (1 - theo) / trials))})
        print(f"  t={t}: emp={emp:.5f} theo={theo:.7f}")
    dump("c1t", {"trials": trials, "seed": seed, "rows": rows})


# ------------------------------------------------------------------ false positives
def exp_fp(trials=20000, seed=99):
    rng = np.random.default_rng(seed)
    out = {}
    for eta in (2, 3):
        x = cbd(rng, eta, (trials, N))
        T = fault_tables("none", trials, rng)
        y = ntt(x, T)
        H = entropy_rows(y)
        out[f"eta={eta}"] = {
            "C1": float(c1_detect(T, 4, rng).mean()),
            "C2": float(c2_detect(y).mean()), "C2_proxy": float(c2_proxy_detect(y).mean()),
            "C3": float(RATS().detect(T).mean()),
            "H_min": float(H.min()), "H_mean": float(H.mean()),
            "distinct_min": int(distinct_rows(y).min()),
        }
        print(f"  eta={eta}: {out[f'eta={eta}']}")
    dump("fp", {"trials": trials, "seed": seed, "res": out})


# ------------------------------------------------------------------ representation
# zetas_asm[128] from pqm4 crypto_kem/ml-kem-768/m4fspeed/ntt.c (Plantard form)
PQM4_ZETAS_ASM = [
 2230699446, 3328631909, 4243360600, 3408622288, 812805467, 2447447570, 1094061961, 1370157786, 2475831253, 249002310, 1028263423, 3594406395, 4205945745, 734105255, 2252632292, 381889553, 372858381, 427045412, 21932846, 3562152210, 752167598, 3417653460, 3157039644, 4196914574, 2265533966, 2112004045, 932791035, 2951903026, 1419184148, 1727534158, 1544330386, 2972545705, 1817845876, 3434425636, 4233039261, 300609006, 1904287092, 2937711185, 2651294021, 975366560, 2781600929, 3889854731, 3935010590, 3929849920, 838608815, 2550660963, 2197155094, 2130066389, 3598276897, 2308109491, 72249375, 3242190693, 815385801, 2382939200, 1228239371, 1884934581, 3466679822, 2889974991, 3696329620, 42575525, 1211467195, 2977706375, 3144137970, 3080919767, 1719793153, 1703020977, 2470670584, 945692709, 3015121229, 345764865, 826997308, 1839778722, 2991898216, 1851390229, 2043625172, 2964804700, 2628071007, 4154339049, 2701610550, 1041165097, 583155668, 483812778, 3288636719, 2696449880, 2122325384, 690239563, 1855260731, 3700200122, 1371447954, 411563403, 3577634219, 976656727, 3718262466, 1979116802, 3098982111, 2708061387, 723783916, 3181552825, 3346694253, 3087370604, 3415073125, 3376368103, 3617629408, 1408862808, 519937465, 1323711759, 3714391964, 1910737929, 836028480, 1474661346, 2773859924, 3580214553, 1143088323, 2546790461, 3191874164, 4012420634, 2221668274, 1563682897, 2417773720, 1327582262, 1059227441, 1583035408, 1174052340, 2722253228, 3786641338, 1141798155, 2779020594, 0]


def exp_repr(trials=2_000_000, seed=3):
    rng = np.random.default_rng(seed)
    R16 = pow(2, 16, Q)
    res = {}
    # (1) reference/PQClean table: signed Montgomery form zeta * 2^16 mod q
    mont = [(int(z) * R16) % Q for z in GENUINE_TABLE]
    res["montgomery_naive_pass"] = sum(pow(v, 256, Q) == 1 for v in mont[1:]) / 127
    res["montgomery_R256"] = pow(R16, 256, Q)
    res["montgomery_aware_pass"] = sum(pow(v, 256, Q) == pow(R16, 256, Q) for v in mont[1:]) / 127
    # (2) pqm4 m4fspeed: 32-bit Plantard words; decode B = (w * q) mod 2^32
    z = np.array(PQM4_ZETAS_ASM, dtype=np.uint64)
    B = (z * Q) % (1 << 32)
    used = B[:127]
    res["plantard_decoded_max"] = int(used.max())
    Rp = (-pow(2, 32, Q)) % Q
    target = pow(Rp, 256, Q)
    res["plantard_target_B256"] = target
    res["plantard_naive_pass"] = float(np.mean([pow(int(b), 256, Q) == 1 for b in used]))
    res["plantard_aware_pass"] = float(np.mean([(b < Q) and pow(int(b), 256, Q) == target for b in used]))
    res["pqm4_padding_entry_127_is_zero"] = int(PQM4_ZETAS_ASM[127]) == 0
    # (3) miss probability of the representation-aware check for random 32-bit words
    w = rng.integers(0, 1 << 32, size=trials, dtype=np.uint64)
    Bw = (w * Q) % (1 << 32)
    inrange = Bw < Q
    res["random_word_inrange_rate"] = float(inrange.mean())
    res["random_word_inrange_theory"] = Q / 2 ** 32
    res["per_sample_miss_theory"] = 256 / 2 ** 32
    # special words
    for name, word in [("0xFFFFFFFF (erased flash)", 0xFFFFFFFF), ("0x00000000", 0)]:
        b = (word * Q) % (1 << 32)
        res[f"special {name}"] = {"B": int(b), "detected": bool(not (0 < b < Q and pow(b, 256, Q) == target))}
    print(json.dumps(res, indent=1))
    dump("repr", res)


# ------------------------------------------------------------------ figures
def figs():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.size": 8, "font.family": "serif"})
    sw = json.load(open(f"{RES}/sweep.json"))
    cs = np.arange(Q)
    fig, ax = plt.subplots(2, 1, figsize=(3.45, 3.2), sharex=True,
                           gridspec_kw={"height_ratios": [1, 1.25]})
    c1 = np.array(sw["C1_detect_by_c"])
    ax[0].scatter(cs[c1 == 0], np.zeros((c1 == 0).sum()), s=2, color="tab:red",
                  label=f"undetected ($c^{{256}}\\equiv 1$, {int((c1==0).sum())} values)")
    ax[0].set_ylim(-0.2, 1.2)
    ax[0].set_yticks([0, 1])
    ax[0].axhline(1, color="tab:blue", lw=0.8, label="detected (all other $c$)")
    ax[0].set_ylabel("C1 detect")
    ax[0].legend(loc="center right", fontsize=6, frameon=False)
    for label, st in [("CBD eta=2", "-"), ("uniform", ":")]:
        H = np.array(sw["inputs"][label]["meanH_by_c"])
        ax[1].plot(cs, H, st, lw=0.6, label=f"mean $H$, input {label.replace('eta', '$\\eta$')}")
    ax[1].axhline(6.0, color="k", lw=0.7, ls="--", label=r"C2 threshold $\tau=6$")
    ax[1].set_ylabel("output entropy (bits)")
    ax[1].set_xlabel("stuck-at constant $c$")
    ax[1].set_ylim(-0.3, 8.5)
    ax[1].annotate("$c=0$", (0, 1.0), xytext=(250, 1.6), fontsize=6,
                   arrowprops=dict(arrowstyle="->", lw=0.5))
    ax[1].annotate("$c=-1$", (Q - 1, 4.9), xytext=(2500, 3.0), fontsize=6,
                   arrowprops=dict(arrowstyle="->", lw=0.5))
    ax[1].annotate("$c=+1$", (1, 4.9), xytext=(300, 3.6), fontsize=6,
                   arrowprops=dict(arrowstyle="->", lw=0.5))
    ax[1].legend(loc="lower right", fontsize=6, frameon=False)
    fig.tight_layout()
    fig.savefig(f"{FIG}/fig_stuck_sweep.pdf")
    print("  -> figures/fig_stuck_sweep.pdf")

    # entropy collapse (regenerated, centered representatives)
    from kyber import centered
    rng = np.random.default_rng(2024)
    while True:
        x = cbd(rng, 2, (N,))
        if x[0] != x[1]:
            break
    g = centered(ntt(x))
    f = centered(ntt(x, np.zeros(128, dtype=np.int64)))
    fig, ax = plt.subplots(1, 2, figsize=(7.0, 2.0))
    ax[0].hist(g, bins=64, range=(-Q // 2, Q // 2), color="tab:blue")
    ax[0].set_title(f"genuine NTT output ($H$ = {entropy_rows(g[None] % Q)[0]:.2f} bits)")
    vals, cnt = np.unique(f, return_counts=True)
    ax[1].bar(vals, cnt, width=60, color="tab:red")
    ax[1].annotate("two values: " + ", ".join(f"{v} ($\\times${c})" for v, c in zip(vals, cnt)),
                   (vals[-1], cnt[-1]), xytext=(250, cnt.max() * 0.75), fontsize=7,
                   arrowprops=dict(arrowstyle="->", lw=0.5))
    ax[1].set_title(f"zero-twiddle output ($H$ = {entropy_rows(f[None] % Q)[0]:.2f} bit)")
    for a in ax:
        a.set_xlim(-Q // 2, Q // 2)
        a.set_xlabel("coefficient value (centered)")
    ax[0].set_ylabel("count")
    fig.tight_layout()
    fig.savefig(f"{FIG}/fig_entropy_collapse.pdf")
    print("  -> figures/fig_entropy_collapse.pdf")


if __name__ == "__main__":
    what = sys.argv[1] if len(sys.argv) > 1 else "all"
    assert self_test()
    steps = {"main": exp_main, "sweep": exp_sweep, "attacks": exp_attacks,
             "c1t": exp_c1t, "fp": exp_fp, "repr": exp_repr, "figs": figs,
             "effsecret": exp_effsecret, "partial": exp_partial}
    order = ["repr", "fp", "c1t", "main", "sweep", "effsecret", "partial", "attacks", "figs"]
    for s in (order if what == "all" else [what]):
        print(f"[{s}]")
        t0 = time.time()
        steps[s]()
        print(f"[{s}] done in {time.time()-t0:.0f}s")
