# ftcm_pqm4 — countermeasures integrated into pqm4 (ML-KEM-768, m4fspeed)

## 1. What is here
| path | content |
|---|---|
| `src/ftcm.c, ftcm.h` | C1 (Plantard-aware sanity check), C2 (distinct-value proxy), RATS (m identical copies, tag = SHA-256 / HMAC-SHA-256 / keyed universal hash), protected `ntt()` wrapper that passes the *verified pointer value* to `ntt_fast` |
| `src/ftcm_inline.c` | "verify-what-you-use" NTT (C reference NTT + inline keyed polynomial hash of the consumed twiddles) |
| `bench/ftbench.c` | benchmark of every component + fault-simulation test (pointer passed to the NTT is replaced) |
| `tools/make_variants.py` | installs the variants into a pqm4 checkout and generates tables/tags (provisioning) |
| `tools/qemu_insn_plugin.c`, `qemu_insn_count.py`, `qemu_kem_count.py` | instruction counting under QEMU (what the paper currently reports) |
| `bench/ftfi.c` | target firmware for instruction-level fault injection (4 configurations) |
| `tools/fi_gdb.py`, `fi_campaign.py`, `fi_summarize.py` | single-fault injection campaign in QEMU + gdb-multiarch |
| `results_qemu/` | the instruction counts used in the cost tables |
| `results_fi/` | fault-injection results used in the fault-injection table |

Variants created next to `crypto_kem/ml-kem-768/m4fspeed` (the unmodified baseline):
`m4fspeed-ftcm-c1`, `-c2`, `-rats` (SHA-256), `-ratsh` (HMAC), `-ratsu` (universal hash),
`-all` (RATS-SHA256 + C1 + C2), `-allu` (RATS-universal + C1 + C2).

## 2. Install
```
git clone --recursive https://github.com/mupq/pqm4.git
python3 ftcm_pqm4/tools/make_variants.py pqm4
```
(Tested with pqm4 commit 5e5cc76, Sept. 2026, arm-none-eabi-gcc 13.2, QEMU 8.2.)

## 3. Cycle counts on a board (needed before submission)
Supported boards include `stm32f4discovery` (STM32F407, the board of Ravi et al.) and
`nucleo-l4r5zi`. Use the same platform for all variants.
```
cd pqm4
# (a) KEM-level cycles for baseline and variants (pqm4's own scripts):
python3 test.py       -p stm32f4discovery ml-kem-768        # functional test, all variants
python3 benchmarks.py -p stm32f4discovery ml-kem-768        # repeat a few times
python3 convert_benchmarks.py md                            # -> Table V (cycles)
# (b) per-component cycles + fault simulation (Table IV):
for v in all allu ratsh; do
  make -j4 PLATFORM=stm32f4discovery IMPLEMENTATION_PATH=crypto_kem/ml-kem-768/m4fspeed-ftcm-$v \
       bin/crypto_kem_ml-kem-768_m4fspeed-ftcm-${v}_ftbench.bin
  st-flash write bin/crypto_kem_ml-kem-768_m4fspeed-ftcm-${v}_ftbench.bin 0x8000000
  python3 hostside/host_unidirectional.py      # prints BENCH / FAULT / INLINE lines, ends with '#'
done
```
`BENCH <name> min <cycles> avg <cycles>`: subtract the `empty (timer overhead)` line.
On the nucleo board flash with OpenOCD instead of st-flash (see pqm4 README).
If you change the optimisation level, run `make clean` first.

## 4. Instruction counts under QEMU (what the current version reports)
```
curl -sSfLO https://raw.githubusercontent.com/qemu/qemu/v8.2.2/include/qemu/qemu-plugin.h
gcc -shared -fPIC -O2 $(pkg-config --cflags glib-2.0) -I. -o tools/libftcminsn.so tools/qemu_insn_plugin.c
cd pqm4 && for v in all allu ratsh; do make PLATFORM=mps2-an386 IMPLEMENTATION_PATH=crypto_kem/ml-kem-768/m4fspeed-ftcm-$v \
     elf/crypto_kem_ml-kem-768_m4fspeed-ftcm-${v}_ftbench.elf; done; cd ..
python3 tools/qemu_insn_count.py pqm4/elf/crypto_kem_ml-kem-768_m4fspeed-ftcm-allu_ftbench.elf --plugin tools/libftcminsn.so
# KEM level: build the *_speed.elf of m4fspeed and every variant for mps2-an386, then
python3 tools/qemu_kem_count.py --plugin tools/libftcminsn.so pqm4/elf/crypto_kem_ml-kem-768_m4fspeed_speed.elf \
        pqm4/elf/crypto_kem_ml-kem-768_m4fspeed-ftcm-*_speed.elf
```
Instruction counts are not cycle counts (loads, multi-register transfers, taken branches and
flash wait states cost extra cycles on the Cortex-M4); use them only for ratios.

## 5. Instruction-level fault injection (QEMU + gdb)
```
sudo apt install gdb-multiarch qemu-system-arm
cp ftcm_pqm4/bench/ftfi.c pqm4/mupq/crypto_kem/
cd pqm4 && make PLATFORM=mps2-an386 IMPLEMENTATION_PATH=crypto_kem/ml-kem-768/m4fspeed-ftcm-allu \
     elf/crypto_kem_ml-kem-768_m4fspeed-ftcm-allu_ftfi.elf && cd ..
python3 ftcm_pqm4/tools/fi_campaign.py pqm4/elf/crypto_kem_ml-kem-768_m4fspeed-ftcm-allu_ftfi.elf --out results_fi
python3 ftcm_pqm4/tools/fi_summarize.py results_fi
```
One fault per run. 'ptr' faults redirect a register that has just received a twiddle-table
address to a zero page; 'data' faults zero the registers loaded from a twiddle table. Every such
instruction is found by single-stepping one execution; up to K (default 3) dynamic instances
per instruction are faulted. Takes ~15 min (single-stepping through gdb is slow).
Configurations (`fi_target`): 0 unprotected, 1 protected in-register (RATS+C1+C2),
2 check-then-reload (TOCTOU), 3 inline-hash C NTT.

## 6. Notes and limitations
* `ftcm_on_fault()` halts by default; a product would zeroize secrets and reset.
* The demo HMAC key in `make_variants.py` and the boot-time key of the universal hash are for
  benchmarking only; a deployment provisions a per-device key and the reference tag in OTP.
* Only the forward NTT is protected (`invntt_fast` and the base multiplication use their own
  tables). The inline variant exists only for the C reference NTT; porting it into
  `ntt_fast` (two instructions per twiddle) is the main open engineering item.
* QEMU's `randombytes` in pqm4 is not random (warning at build time); irrelevant for costs.
