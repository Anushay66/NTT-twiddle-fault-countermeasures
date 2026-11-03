#!/usr/bin/env python3
"""Summarize results_fi/fi_target*.json (see fi_campaign.py).

A 'ptr' site is kept only if the instruction can produce an address (loads,
register restores, moves, add/sub/adr address arithmetic); values that merely
happen to fall into the table address range (multiplications, shifts right,
extensions, logic ops) are discarded as coincidences.
"""
import glob, json, os, re, sys

NAMES = {0: "Baseline (unprotected)", 1: "RATS+C1+C2, in-register", 2: "RATS, check-then-reload",
         3: "Inline hash (C NTT)"}
ADDR_OPS = ("ldr", "ldm", "vldm", "pop", "mov", "add", "sub", "adr")
BAD = ("lsr", "asr", "uxt", "sxt", "mul", "orr", "eor", "and")

def keep(r):
    if r["kind"] != "ptr":
        return True
    mn = r["asm"].split()[0]
    return mn.startswith(ADDR_OPS) and not any(b in r["asm"] for b in BAD)

def cls(r):
    if r.get("crash"): return "crash"
    if r["mask"]: return "detected"
    if r["correct"]: return "benign"
    return "lowH" if r["distinct"] <= 64 else "silent"

def main(d):
    out = {}
    for f in sorted(glob.glob(os.path.join(d, "fi_target*.json"))):
        j = json.load(open(f)); t = j["target"]
        rows = {}
        for r in j["runs"]:
            if not keep(r):
                continue
            c = cls(r); k = r["kind"]
            rows.setdefault(k, {}).setdefault(c, 0)
            rows[k][c] += 1
        out[NAMES[t]] = rows
        for k in ("ptr", "data"):
            v = rows.get(k, {}); n = sum(v.values())
            print(f"{NAMES[t]:26s} {k:4s} runs={n:3d}  " + "  ".join(
                f"{c}={v.get(c,0)}" for c in ("detected", "benign", "silent", "lowH", "crash")))
    json.dump(out, open(os.path.join(d, "summary_filtered.json"), "w"), indent=1)

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "results_fi")
