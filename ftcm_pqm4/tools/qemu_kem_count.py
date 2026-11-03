#!/usr/bin/env python3
"""
KEM-level instruction counts (NOT cycles) of pqm4 speed binaries under QEMU,
using the toggle mode of the plugin on hal_get_time().

    python3 tools/qemu_kem_count.py --plugin tools/libftcminsn.so \
        <pqm4>/elf/crypto_kem_ml-kem-768_m4fspeed_speed.elf \
        <pqm4>/elf/crypto_kem_ml-kem-768_m4fspeed-ftcm-all_speed.elf ...
"""
import argparse
import json
import subprocess


def sym(elf, name):
    out = subprocess.run(["arm-none-eabi-nm", elf], capture_output=True, text=True).stdout
    for line in out.splitlines():
        p = line.split()
        if len(p) == 3 and p[2] == name:
            return int(p[0], 16)
    raise SystemExit(f"{name} not found in {elf}")


def run(elf, plugin):
    t = sym(elf, "hal_get_time")
    cmd = ["qemu-system-arm", "-M", "mps2-an386", "-nographic", "-semihosting",
           "-plugin", f"{plugin},toggle={hex(t)}", "-d", "plugin", "-kernel", elf]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    deltas, ok = [], True
    for line in p.stdout:
        if line.startswith("DELTA"):
            deltas.append(int(line.split()[1]))
        if "ERROR" in line:
            ok = False
        if line.strip() == "#":
            p.kill()
            break
    d = deltas[1:]                       # drop everything before the first call
    it = (len(d) + 1) // 6
    kp = [d[6 * i] for i in range(it)]
    en = [d[6 * i + 2] for i in range(it)]
    de = [d[6 * i + 4] for i in range(it)]
    return {"keypair": min(kp), "encaps": min(en), "decaps": min(de), "iterations": it, "ok": ok}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("elfs", nargs="+")
    ap.add_argument("--plugin", required=True)
    ap.add_argument("--json")
    a = ap.parse_args()
    res = {}
    base = None
    for elf in a.elfs:
        name = elf.split("ml-kem-768_")[-1].replace("_speed.elf", "")
        r = run(elf, a.plugin)
        res[name] = r
        if base is None:
            base = r
        print(f"{name:22s} keypair {r['keypair']:9d} ({r['keypair']/base['keypair']:.3f}x)  "
              f"encaps {r['encaps']:9d} ({r['encaps']/base['encaps']:.3f}x)  "
              f"decaps {r['decaps']:9d} ({r['decaps']/base['decaps']:.3f}x)  it={r['iterations']}")
    if a.json:
        json.dump(res, open(a.json, "w"), indent=2)


if __name__ == "__main__":
    main()
