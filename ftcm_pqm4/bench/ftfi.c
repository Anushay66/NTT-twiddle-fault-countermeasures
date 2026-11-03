/*
 * ftfi.c -- target firmware for instruction-level fault injection (see
 * tools/fi_campaign.py).  One target is executed per run, selected by the
 * debugger through `fi_target`:
 *   0  baseline   : unprotected ntt(): pointer loaded from the literal pool
 *   1  protected  : ftcm_ntt_checked() -- RATS + C1 + C2, the verified pointer
 *                   value is passed in a register to ntt_fast (in-register)
 *   2  naive      : RATS check, then the NTT re-loads its own pointer (TOCTOU)
 *   3  inline     : C reference NTT with inline hashing of consumed twiddles
 * Results are left in global variables read by the debugger at fi_done().
 */
#include <stdint.h>
#include <string.h>
#include "hal.h"
#include "ftcm.h"

extern void ntt_fast(int16_t *, const int32_t *);
extern const int32_t zetas_asm[128];

int16_t fi_poly[256] __attribute__((aligned(8)));
int16_t fi_ref[256] __attribute__((aligned(8)));
int32_t fi_zero_page[256] __attribute__((aligned(8)));     /* "zero region" */
volatile int fi_target;
volatile unsigned fi_mask;
volatile int fi_released, fi_correct, fi_distinct;

void __attribute__((noinline)) fi_begin(void) { __asm__ volatile("nop"); }
void __attribute__((noinline)) fi_done(void) { __asm__ volatile("nop"); }

/* the unprotected wrapper: loads the table address itself (Ravi et al.'s target) */
void __attribute__((noinline)) fi_ntt_reload(int16_t *p) { ntt_fast(p, zetas_asm); }

unsigned __attribute__((noinline)) t_baseline(int16_t *p) {
    fi_ntt_reload(p);
    return 0;
}
unsigned __attribute__((noinline)) t_protected(int16_t *p) {
    return ftcm_ntt_checked(p, 0);
}
unsigned __attribute__((noinline)) t_naive(int16_t *p) {
    unsigned idx;
    if (ftcm_rats_select_verify(0, &idx) == 0) {
        memset(p, 0, 512);
        return FTCM_DET_RATS;
    }
    fi_ntt_reload(p);                 /* TOCTOU: pointer re-loaded after the check */
    return 0;
}
unsigned __attribute__((noinline)) t_inline(int16_t *p) {
    return ftcm_ntt_ref_inline(p, ftcm_zetas_ref) ? FTCM_DET_RATS : 0;
}

static unsigned distinct_mod_q(const int16_t *p) {
    static uint32_t bm[(3329 + 31) / 32];
    memset(bm, 0, sizeof(bm));
    unsigned d = 0;
    for (int i = 0; i < 256; i++) {
        int32_t v = p[i] % 3329;
        if (v < 0) v += 3329;
        if (!(bm[v >> 5] & (1u << (v & 31)))) { d++; bm[v >> 5] |= 1u << (v & 31); }
    }
    return d;
}

int main(void) {
    hal_setup(CLOCK_FAST);
    ftcm_inline_init(0x12345678u);
    ftcm_rats_init(0x0badcafeu, 0x13572468u);
    uint32_t s = 0x2545F491u;
    for (int i = 0; i < 256; i++) {           /* deterministic CBD-like input */
        s = s * 1664525u + 1013904223u;
        fi_poly[i] = (int16_t)(((s >> 28) & 1) + ((s >> 29) & 1) - ((s >> 30) & 1) - ((s >> 31) & 1));
    }
    memcpy(fi_ref, fi_poly, sizeof(fi_poly));
    if (fi_target == 3) {
        ftcm_ntt_ref(fi_ref);
    } else {
        ntt_fast(fi_ref, zetas_asm);
    }
    unsigned m = 0;
    fi_begin();
    switch (fi_target) {
        case 0: m = t_baseline(fi_poly); break;
        case 1: m = t_protected(fi_poly); break;
        case 2: m = t_naive(fi_poly); break;
        default: m = t_inline(fi_poly); break;
    }
    fi_done();
    fi_mask = m;
    fi_released = (m == 0);
    fi_correct = fi_released && (memcmp(fi_poly, fi_ref, sizeof(fi_poly)) == 0);
    fi_distinct = (int)distinct_mod_q(fi_poly);
    fi_done();
    hal_send_str("#");
    for (;;);
    return 0;
}
