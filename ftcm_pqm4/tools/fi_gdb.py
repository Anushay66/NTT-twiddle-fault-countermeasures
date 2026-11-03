# gdb-python script executed inside gdb-multiarch (see fi_campaign.py).
# Single-fault, instruction-level fault injection on the ftfi firmware in QEMU:
#   'ptr'  : a register that receives a twiddle-table address is redirected to
#            a zero page right after the instruction that wrote it
#            (models a corrupted pointer load / pointer register, Ravi et al.)
#   'data' : the destination register(s) of a load that reads twiddle words
#            from a table are zeroed (models a fault on the data transfer)
import gdb, json, os, re

PORT = os.environ["FI_PORT"]; TARGET = int(os.environ["FI_TARGET"])
OUT = os.environ["FI_OUT"]; K = int(os.environ.get("FI_K", "3"))
gdb.execute("set pagination off"); gdb.execute("set confirm off")
gdb.execute(f"target remote :{PORT}", to_string=True)

def addr(sym):
    return int(gdb.parse_and_eval(f"(unsigned int)&{sym}")) & 0xfffffffe
A = {s: addr(s) for s in ["main", "fi_begin", "fi_done", "fi_target", "fi_mask", "fi_released",
                          "fi_correct", "fi_distinct", "fi_zero_page", "zetas_asm",
                          "ftcm_tw_copies", "ftcm_zetas_ref", "HardFault_Handler"]}
TABLES = [(A["zetas_asm"], A["zetas_asm"] + 512), (A["ftcm_tw_copies"], A["ftcm_tw_copies"] + 4 * 512),
          (A["ftcm_zetas_ref"], A["ftcm_zetas_ref"] + 256)]
def in_tab(v): return any(lo <= v < hi + 8 for lo, hi in TABLES)   # +8: post-increment past the end
REGS = [f"r{i}" for i in range(13)] + ["lr"]

def rd(r): return int(gdb.selected_frame().read_register(r)) & 0xffffffff
def regs(): return {r: rd(r) for r in REGS}
def pc(): return rd("pc") & 0xfffffffe
def wr32(a, v): gdb.execute(f"set var *(unsigned int*){a} = {v}")
def rd32(a): return int(gdb.parse_and_eval(f"*(unsigned int*){a}")) & 0xffffffff

def run_to(a, ignore=0):
    b = gdb.Breakpoint(f"*{a}", internal=True); b.ignore_count = ignore
    hf = gdb.Breakpoint(f"*{A['HardFault_Handler']}", internal=True)
    gdb.execute("continue", to_string=True)
    p = pc(); b.delete(); hf.delete()
    return p != A["HardFault_Handler"]

def reset_to_begin():
    gdb.execute("monitor system_reset", to_string=True)
    gdb.execute("maintenance flush register-cache", to_string=True)
    run_to(A["main"]); wr32(A["fi_target"], TARGET); run_to(A["fi_begin"])

def results():
    return {"mask": rd32(A["fi_mask"]), "released": rd32(A["fi_released"]),
            "correct": rd32(A["fi_correct"]), "distinct": rd32(A["fi_distinct"])}

def dests(asm):
    m = asm.split(None, 1)
    if len(m) < 2: return []
    ops = m[1].split("[")[0]
    if "{" in m[1] and m[0].startswith("vld"):
        body = m[1][m[1].index("{") + 1:m[1].index("}")]
        out = []
        for part in body.split(","):
            part = part.strip()
            if "-" in part:
                a, b = part.split("-"); pre = a[0]
                out += [f"{pre}{i}" for i in range(int(a[1:]), int(b.strip()[1:]) + 1)]
            else: out.append(part)
        return out
    return [t.strip() for t in ops.split(",") if re.fullmatch(r"\s*(r\d+|lr|ip|fp|sl|s\d+|d\d+)\s*", t)]

def base_reg(asm):
    m = re.search(r"\[(\w+)", asm)
    if m: return m.group(1)
    m = re.match(r"\s*vldm\w*\s+(\w+)", asm)
    return m.group(1) if m else None

ALIAS = {"ip": "r12", "fp": "r11", "sl": "r10", "sb": "r9"}

def is_pointer_producer(mn, asm, before):
    """True if the instruction plausibly produces a table *address*: a load from
    the literal pool / stack, a pointer write-back, a register restore, or
    address arithmetic on a register that already holds a table address.
    Excludes values that only coincidentally fall into the table range."""
    toks = [ALIAS.get(t, t) for t in re.findall(r"\b(r\d+|lr|ip|fp|sl|sb|sp|pc)\b", asm)]
    if mn.startswith(("ldr", "vldm")):
        b = base_reg(asm); b = ALIAS.get(b, b)
        return b in ("pc", "sp") or (b in before and in_tab(before[b]))
    if mn.startswith(("ldm", "pop")):
        return "sp" in toks or mn.startswith("pop")
    if mn.startswith(("mov", "add", "sub", "adr")):
        srcs = toks[1:]
        return "pc" in srcs or mn.startswith("adr") or any(x in before and in_tab(before[x]) for x in srcs)
    return False

# ---------------- discovery: single-step through the target once ----------
reset_to_begin()
arch = gdb.selected_frame().architecture()
sites, occ, steps = {}, {}, 0
while pc() != A["fi_done"]:
    p = pc(); asm = arch.disassemble(p)[0]["asm"]
    before = regs()
    gdb.execute("stepi", to_string=True); steps += 1
    after = regs()
    n = occ[p] = occ.get(p, 0) + 1
    mn = asm.split()[0] if asm.split() else ""
    for r in REGS:
        if after[r] != before[r] and in_tab(after[r]) and is_pointer_producer(mn, asm, before):
            sites.setdefault(("ptr", p, r), []).append(n)
    if mn.startswith(("ldr", "ldm", "vld")):
        b = base_reg(asm); b = ALIAS.get(b, b)
        if b in before and in_tab(before[b]):
            d = [ALIAS.get(x, x) for x in dests(asm)]
            if d: sites.setdefault(("data", p, ",".join(d)), []).append(n)
    if steps > 200000: break
golden = results()   # values not yet final here; read later

def pick(lst):
    if len(lst) <= K: return lst
    idx = sorted(set([0, len(lst) // 2, len(lst) - 1] + [int(i * (len(lst) - 1) / (K - 1)) for i in range(K)]))
    return [lst[i] for i in idx][:max(K, 3)]

# ---------------- injection runs ------------------------------------------
runs = []
for (kind, p, r), lst in sorted(sites.items(), key=lambda x: (x[0][1], x[0][0])):
    for n in pick(lst):
        reset_to_begin()
        b = gdb.Breakpoint(f"*{p}", internal=True); b.ignore_count = n - 1
        gdb.execute("continue", to_string=True); b.delete()
        gdb.execute("stepi", to_string=True)
        val = A["fi_zero_page"] if kind == "ptr" else 0
        for reg in r.split(","):
            gdb.execute(f"set ${reg} = {val}")
        ok = run_to(A["fi_done"], ignore=1)
        res = results() if ok else {"crash": 1}
        res.update({"kind": kind, "pc": hex(p), "reg": r, "occurrence": n, "of": len(lst),
                    "asm": arch.disassemble(p)[0]["asm"]})
        runs.append(res)
json.dump({"target": TARGET, "steps": steps, "n_sites": len(sites), "runs": runs}, open(OUT, "w"), indent=1)
gdb.execute("monitor quit", to_string=True)
