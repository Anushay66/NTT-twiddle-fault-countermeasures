/*
 * ftbench.c -- cycle benchmark + fault-simulation test for the ftcm
 * countermeasures on pqm4 (ML-KEM-768, m4fspeed).  Built by pqm4 as
 *   elf/crypto_kem_ml-kem-768_m4fspeed-ftcm-all_ftbench.elf
 * (see ../README.md).  All timings use pqm4's hal_get_time(), i.e. the DWT
 * cycle counter on real boards.  Under QEMU the reported times are NOT cycles;
 * use tools/qemu_insn_plugin.c for instruction counts instead.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "hal.h"
#include "randombytes.h"
#include "ftcm.h"

extern void ntt_fast(int16_t *, const int32_t *);
extern const int32_t zetas_asm[128];

#ifndef FTBENCH_REPS
#define FTBENCH_REPS 50
#endif

static int16_t poly[256] __attribute__((aligned(8)));
static int16_t ref_out[256] __attribute__((aligned(8)));
static int16_t in_copy[256] __attribute__((aligned(8)));
static int32_t fault_buf[128] __attribute__((aligned(8)));
static int16_t fault_buf16[128] __attribute__((aligned(8)));
static char out[160];

/* markers for the QEMU instruction-count plugin (never inlined) */
void __attribute__((noinline)) ftcm_mark_begin(void) { __asm__ volatile("nop"); }
void __attribute__((noinline)) ftcm_mark_end(void) { __asm__ volatile("nop"); }

static void fill_poly(void) {
    for (int i = 0; i < 256; i++) {
        uint32_t r = ftcm_rand32();
        /* CBD-like small coefficients in [-2, 2] */
        poly[i] = (int16_t)(((r & 1) + ((r >> 1) & 1)) - (((r >> 2) & 1) + ((r >> 3) & 1)));
    }
}

static void report(const char *label, uint64_t best, uint64_t sum) {
    snprintf(out, sizeof(out), "BENCH %-34s min %8llu  avg %8llu", label,
             (unsigned long long)best, (unsigned long long)(sum / FTBENCH_REPS));
    hal_send_str(out);
}

#define MEASURE(label, stmt)                                         \
    do {                                                             \
        uint64_t best = ~0ull, sum = 0;                              \
        for (int rep = 0; rep < FTBENCH_REPS; rep++) {               \
            fill_poly();                                             \
            uint64_t t0 = hal_get_time();                            \
            ftcm_mark_begin();                                       \
            stmt;                                                    \
            ftcm_mark_end();                                         \
            uint64_t t1 = hal_get_time();                            \
            uint64_t d = t1 - t0;                                    \
            sum += d;                                                \
            if (d < best) best = d;                                  \
        }                                                            \
        report(label, best, sum);                                    \
    } while (0)

static volatile int sink;
static unsigned idx_sink;

static void fault_case(const char *label, const int32_t *ptr) {
    fill_poly();
    memcpy(in_copy, poly, sizeof(poly));
    memcpy(ref_out, poly, sizeof(poly));
    ntt_fast(ref_out, zetas_asm);                 /* genuine result */
    unsigned m = ftcm_ntt_checked(poly, ptr);
    int correct = (m == 0) && (memcmp(poly, ref_out, sizeof(poly)) == 0);
    snprintf(out, sizeof(out), "FAULT %-34s C1=%u C2=%u RATS=%u released=%s output-correct=%s",
             label, (m & FTCM_DET_C1) ? 1 : 0, (m & FTCM_DET_C2) ? 1 : 0,
             (m & FTCM_DET_RATS) ? 1 : 0, m ? "no" : "yes", m ? "-" : (correct ? "yes" : "NO"));
    hal_send_str(out);
}

static void inline_case(const char *label, const int16_t *zp) {
    fill_poly();
    int det = ftcm_ntt_ref_inline(poly, zp);
    snprintf(out, sizeof(out), "INLINE %-33s detected=%d", label, det);
    hal_send_str(out);
}

int main(void) {
    hal_setup(CLOCK_BENCHMARK);
    hal_send_str("==========================");
    snprintf(out, sizeof(out), "ftbench: C1=%d(t=%d) C2=%d(dmin=%d) RATS=%d(m=%d,mode=%s) reps=%d",
             FTCM_C1, FTCM_C1_T, FTCM_C2, FTCM_C2_DMIN, FTCM_RATS, FTCM_RATS_M,
             FTCM_RATS_MODE == 2 ? "poly-hash" : (FTCM_RATS_MODE ? "HMAC-SHA256" : "SHA256"), FTBENCH_REPS);
    hal_send_str(out);
    uint8_t kb[4];
    randombytes(kb, 4);
    ftcm_inline_init((uint32_t)kb[0] | ((uint32_t)kb[1] << 8) | ((uint32_t)kb[2] << 16) |
                     ((uint32_t)kb[3] << 24));
    ftcm_rats_init(ftcm_rand32(), ftcm_rand32());

    /* ------------------------------------------------ cycle measurements */
    MEASURE("empty (timer overhead)", (void)0);
    MEASURE("ntt_fast (unprotected)", ntt_fast(poly, zetas_asm));
    MEASURE("C1 t=1", sink = ftcm_c1_check(zetas_asm, 1));
    MEASURE("C1 t=2", sink = ftcm_c1_check(zetas_asm, 2));
    MEASURE("C1 t=4", sink = ftcm_c1_check(zetas_asm, 4));
    MEASURE("C1 t=8", sink = ftcm_c1_check(zetas_asm, 8));
    MEASURE("C2 distinct-count proxy", sink = ftcm_c2_check(poly, FTCM_C2_DMIN));
    MEASURE("RATS select+verify", sink = (ftcm_rats_select_verify(0, &idx_sink) != 0));
    MEASURE("protected NTT (this config)", sink = ftcm_ntt_checked(poly, 0));
    MEASURE("ref C NTT (PQClean-style)", ftcm_ntt_ref(poly));
    MEASURE("ref C NTT + inline hash", sink = ftcm_ntt_ref_inline(poly, ftcm_zetas_ref));

    /* ------------------------------------------------ fault simulation
     * The pointer passed to the NTT is replaced, modelling a corrupted
     * twiddle-pointer register (Ravi et al.).  */
    memset(fault_buf, 0, sizeof(fault_buf));
    fault_case("zero (pointer -> zero page)", fault_buf);
    for (int i = 0; i < 128; i++) fault_buf[i] = (int32_t)0xFFFFFFFF;
    fault_case("stuck 0xFFFFFFFF (erased flash)", fault_buf);
    for (int i = 0; i < 128; i++) fault_buf[i] = zetas_asm[0];
    fault_case("stuck at a VALID twiddle word", fault_buf);
    for (int i = 0; i < 128; i++) fault_buf[i] = (int32_t)ftcm_rand32();
    fault_case("random redirection", fault_buf);
    fault_case("shifted pointer (+4 bytes)", zetas_asm + 1);
    fault_case("other genuine copy (benign)", ftcm_tw_copies[FTCM_RATS_M - 1]);
    fault_case("no fault", 0);

    memset(fault_buf16, 0, sizeof(fault_buf16));
    inline_case("zero", fault_buf16);
    inline_case("shifted pointer (+2 bytes)", ftcm_zetas_ref + 1);
    inline_case("no fault", ftcm_zetas_ref);
    snprintf(out, sizeof(out), "ftcm_fault_count=%u", ftcm_fault_count);
    hal_send_str(out);
    hal_send_str("#");
    for (;;);
    return 0;
}
