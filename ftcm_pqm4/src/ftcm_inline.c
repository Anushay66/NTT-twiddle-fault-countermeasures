/*
 * ftcm_inline.c -- "verify-what-you-use" variant (TOCTOU-resistant).
 *
 * The integrity check is folded into the NTT itself: every twiddle factor is
 * absorbed into a keyed polynomial hash over GF(p), p = 2^31 - 1, at the moment
 * it is loaded for a butterfly, and the hash is compared with the provisioned
 * value before the output is released.  A pointer fault anywhere before or
 * during the transform therefore changes the hash, unlike a check that runs
 * before the NTT re-loads its own pointer.
 *
 * Collision bound (polynomial evaluation hash): two distinct 127-word sequences
 * collide for at most 127 keys out of p, i.e. Pr <= 127/(2^31-1) < 2^-24 for a
 * key unknown to the fault (the fault model cannot adapt memory contents to K).
 * Two independent keys give < 2^-48.
 *
 * The NTT below is the PQClean/FIPS-203 reference NTT (16-bit Montgomery
 * zetas) so that the overhead can be compared against an identical baseline;
 * porting the same 2-instruction-per-twiddle accumulation into ntt_fast is
 * future work (see paper, Sec. "TOCTOU").
 */
#include <stdint.h>
#include "ftcm.h"
#include "ftcm_tag.h"   /* generated: FTCM_ZETAS_REF_INIT (computed, not typed) */

#define KQ 3329
#define QINV (-3327)

const int16_t ftcm_zetas_ref[128] = { FTCM_ZETAS_REF_INIT };

static int16_t montgomery_reduce(int32_t a) {
    int16_t t = (int16_t)a * QINV;
    return (int16_t)((a - (int32_t)t * KQ) >> 16);
}
static int16_t fqmul(int16_t a, int16_t b) {
    return montgomery_reduce((int32_t)a * b);
}

void ftcm_ntt_ref(int16_t r[256]) {
    unsigned len, start, j, k = 1;
    int16_t t, zeta;
    for (len = 128; len >= 2; len >>= 1) {
        for (start = 0; start < 256; start = j + len) {
            zeta = ftcm_zetas_ref[k++];
            for (j = start; j < start + len; j++) {
                t = fqmul(zeta, r[j + len]);
                r[j + len] = r[j] - t;
                r[j] = r[j] + t;
            }
        }
    }
}

#define P31 0x7fffffffu
static uint32_t ftcm_key = 0, ftcm_expected = 0;

static inline uint32_t mulmod_p31(uint32_t a, uint32_t b) {
    uint64_t x = (uint64_t)a * b;
    uint32_t lo = (uint32_t)(x & P31), hi = (uint32_t)(x >> 31);
    uint32_t s = lo + hi;
    return (s >= P31) ? s - P31 : s;
}

/* h <- (h + w) * K  mod p   (Horner form of the polynomial hash) */
#define ABSORB(h, w) (h) = mulmod_p31((h) + ((uint32_t)(uint16_t)(w)), ftcm_key)

int ftcm_ntt_ref_inline(int16_t r[256], const int16_t *zp) {
    unsigned len, start, j, k = 1;
    int16_t t, zeta;
    uint32_t h = 0;
    for (len = 128; len >= 2; len >>= 1) {
        for (start = 0; start < 256; start = j + len) {
            zeta = zp[k++];
            ABSORB(h, zeta);
            for (j = start; j < start + len; j++) {
                t = fqmul(zeta, r[j + len]);
                r[j + len] = r[j] - t;
                r[j] = r[j] + t;
            }
        }
    }
    if (h != ftcm_expected) {
        for (j = 0; j < 256; j++) {
            r[j] = 0;           /* never release the faulty output */
        }
        return 1;
    }
    return 0;
}

void ftcm_inline_init(uint32_t key) {
    ftcm_key = (key % (P31 - 1)) + 1;
    uint32_t h = 0;
    for (unsigned k = 1; k < 128; k++) {
        ABSORB(h, ftcm_zetas_ref[k]);
    }
    ftcm_expected = h;
}
