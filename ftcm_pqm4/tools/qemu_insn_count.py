#!/usr/bin/env python3
"""
Instruction counts (NOT cycles) of the ftbench measurements under QEMU.

    python3 tools/qemu_insn_count.py <pqm4>/elf/crypto_kem_ml-kem-768_m4fspeed-ftcm-all_ftbench.elf \
            --plugin tools/libftcminsn.so [--json out.json]

Build the plugin first (QEMU 8.x headers, glib):
    curl -sSfLO https://raw.githubusercontent.com/qemu/qemu/v8.2.2/include/qemu/qemu-plugin.h
    gcc -shared -fPIC -O2 $(pkg-config --cflags glib-2.0) -I. -o tools/libftcminsn.so tools/qemu_insn_plugin.c
"""
import argparse
import json
import re
import statistics
import subprocess


def sym(elf, name):
    out = subprocess.run(["arm-none-eabi-nm", elf], capture_output=True, text=True).stdout
    for line in out.splitlines():
        p = line.split()
        if len(p) == 3 and p[2] == name:
            return int(p[0], 16)
    raise SystemExit(f"symbol {name} not found")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("elf")
    ap.add_argument("--plugin", required=True)
    ap.add_argument("--reps", type=int, default=50)
    ap.add_argument("--json")
    a = ap.parse_args()
    b, e = sym(a.elf, "ftcm_mark_begin"), sym(a.elf, "ftcm_mark_end")
    cmd = ["qemu-system-arm", "-M", "mps2-an386", "-nographic", "-semihosting",
           "-plugin", f"{a.plugin},begin={hex(b)},end={hex(e)}", "-d", "plugin",
           "-kernel", a.elf]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    labels, regions, other = [], [], []
    for line in p.stdout:
        line = line.rstrip()
        if line.startswith("REGION"):
            regions.append(int(line.split()[1]))
        elif line.startswith("BENCH"):
            labels.append(re.match(r"BENCH (.*?)\s+min", line).group(1).strip())
        elif line.startswith(("FAULT", "INLINE", "ftbench", "ftcm_")):
            other.append(line)
        if line.strip() == "#":
            p.kill()
            break
    assert len(regions) == a.reps * len(labels), (len(regions), len(labels))
    res = {}
    for i, lab in enumerate(labels):
        r = regions[i * a.reps:(i + 1) * a.reps]
        res[lab] = {"min": min(r), "median": statistics.median(r), "max": max(r)}
    base = res[labels[0]]["median"]
    print(f"{'measurement':36s} {'insn(median)':>12s} {'minus marker':>12s}")
    for lab in labels:
        m = res[lab]["median"]
        res[lab]["net_median"] = m - base
        print(f"{lab:36s} {m:12.0f} {m-base:12.0f}")
    for line in other:
        print(line)
    if a.json:
        json.dump({"insn": res, "functional": other}, open(a.json, "w"), indent=2)


if __name__ == "__main__":
    main()
