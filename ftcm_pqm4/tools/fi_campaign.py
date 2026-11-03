#!/usr/bin/env python3
"""
Instruction-level single-fault injection campaign on the ftfi firmware (QEMU + gdb).

    python3 tools/fi_campaign.py <pqm4>/elf/crypto_kem_ml-kem-768_m4fspeed-ftcm-allu_ftfi.elf \
            --out results_fi [--targets 0 1 2 3] [--k 3]

Targets: 0 baseline, 1 protected (RATS+C1+C2, in-register), 2 naive check-then-reload,
3 inline-hash C NTT.  For every instruction that writes a twiddle-table address into a
register ('ptr') or loads twiddle words from a table ('data'), up to K dynamic instances
are faulted (one fault per run).  Outcome classes: detected / released correct (benign) /
released wrong / released low-entropy (<=64 distinct values) / crash.
"""
import argparse, json, os, subprocess, time

HERE = os.path.dirname(os.path.abspath(__file__))
NAMES = {0: "baseline (unprotected)", 1: "RATS+C1+C2, in-register", 2: "RATS, check-then-reload",
         3: "inline hash (C NTT)"}

def classify(r):
    if r.get("crash"): return "crash"
    if r["mask"]: return "detected"
    if r["correct"]: return "benign"
    return "low-entropy" if r["distinct"] <= 64 else "silent"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("elf"); ap.add_argument("--out", default="results_fi")
    ap.add_argument("--targets", type=int, nargs="+", default=[0, 1, 2, 3])
    ap.add_argument("--k", type=int, default=3); ap.add_argument("--port", type=int, default=3333)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    summary = {}
    for t in a.targets:
        out = os.path.join(a.out, f"fi_target{t}.json")
        q = subprocess.Popen(["qemu-system-arm", "-M", "mps2-an386", "-nographic", "-semihosting",
                              "-gdb", f"tcp::{a.port}", "-S", "-kernel", a.elf],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.5)
        env = dict(os.environ, FI_PORT=str(a.port), FI_TARGET=str(t), FI_OUT=out, FI_K=str(a.k))
        t0 = time.time()
        subprocess.run(["gdb-multiarch", "-q", "-batch", "-nx", "-ex", "set architecture arm",
                        "-ex", f"file {a.elf}", "-x", os.path.join(HERE, "fi_gdb.py")], env=env,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        q.kill()
        d = json.load(open(out))
        tab = {}
        for r in d["runs"]:
            k = (r["kind"], classify(r))
            tab[k] = tab.get(k, 0) + 1
        summary[NAMES[t]] = {"steps": d["steps"], "sites": d["n_sites"], "runs": len(d["runs"]),
                             "outcomes": {f"{k[0]}:{k[1]}": v for k, v in sorted(tab.items())}}
        print(f"{NAMES[t]:28s} steps={d['steps']:6d} sites={d['n_sites']:4d} runs={len(d['runs']):4d} "
              f"{summary[NAMES[t]]['outcomes']}  ({time.time()-t0:.0f}s)", flush=True)
    json.dump(summary, open(os.path.join(a.out, "summary.json"), "w"), indent=1)

if __name__ == "__main__":
    main()
