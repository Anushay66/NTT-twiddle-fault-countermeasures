/*
 * ftcm.c -- countermeasures C1, C2, C3 (RATS) for the pqm4 ML-KEM m4fspeed NTT.
 * See ftcm.h.  The code is deliberately straightforward C so that the cost of
 * each countermeasure can be measured in isolation with pqm4's cycle counter.
 */
#include <string.h>
#include "ftcm.h"
#include "ftcm_tag.h"     /* generated: FTCM_ZETAS_ASM_INIT, tags, HMAC key */
#include "sha2.h"
#include "randombytes.h"

#define Q 3329u

volatile unsigned ftcm_fault_count = 0;

/* ---------------------------------------------------------------- PRNG
 * xorshift32 seeded once from randombytes(); used only to pick C1 sample
 * indices and the RATS copy index (unpredictability, not secrecy). */
static uint32_t ftcm_state = 0;
uint32_t ftcm_rand32(void) {
    if (ftcm_state == 0) {
        uint8_t b[4];
        randombytes(b, 4);
        ftcm_state = ((uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) |
                      ((uint32_t)b[3] << 24)) | 1u;
    }
    uint32_t x = ftcm_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    ftcm_state = x;
    return x;
}

/* ---------------------------------------------------------------- C1
 * pqm4 m4fspeed stores each twiddle as a 32-bit Plantard word w with
 *     B = (w * q) mod 2^32  in [1, q)   and   B = zeta^k * (-2^32) mod q.
 * Hence a genuine word satisfies  B < q  and  B^256 == ((-2^32) mod q)^256
 * == 754 (mod q).  A uniformly random 32-bit word passes the range test with
 * probability q/2^32 (q is odd, so w -> w*q is a bijection mod 2^32) and the
 * order test with probability 256/q: per-sample miss probability 256/2^32. */
#define FTCM_PLANTARD_B256 754u
int ftcm_c1_check(const int32_t *tw, unsigned t) {
    for (unsigned j = 0; j < t; j++) {
        uint32_t idx = ftcm_rand32() % FTCM_TW_USED;
        uint32_t b = (uint32_t)tw[idx] * Q;          /* mod 2^32 */
        if (b == 0 || b >= Q) {
            return 1;
        }
        uint32_t x = b;
        for (int s = 0; s < 8; s++) {
            x = (x * x) % Q;
        }
        if (x != FTCM_PLANTARD_B256) {
            return 1;
        }
    }
    return 0;
}

/* ---------------------------------------------------------------- C2
 * Distinct-value proxy for output entropy: genuine outputs have >= 233
 * distinct values out of 256 (empirically, 40k trials); a zero-twiddle output
 * has at most 2.  Bitmap over Z_q (417 bytes on the stack).  */
int ftcm_c2_check(const int16_t *poly, unsigned dmin) {
    uint32_t bm[(Q + 31) / 32];
    memset(bm, 0, sizeof(bm));
    unsigned distinct = 0;
    for (int i = 0; i < 256; i++) {
        int32_t v = poly[i] % (int32_t)Q;
        if (v < 0) {
            v += Q;
        }
        uint32_t m = 1u << (v & 31), *w = &bm[v >> 5];
        distinct += (*w & m) == 0;
        *w |= m;
    }
    return distinct < dmin;
}

/* ---------------------------------------------------------------- C3 RATS
 * m byte-identical copies; ONE tag over the table contents (revision option
 * (a)): the tag authenticates what is actually fetched; redirection to another
 * genuine copy is functionally benign and is not claimed to be detected. */
const int32_t ftcm_tw_copies[FTCM_RATS_M][FTCM_TW_WORDS] __attribute__((aligned(16))) = {
#if FTCM_RATS_M >= 1
    { FTCM_ZETAS_ASM_INIT },
#endif
#if FTCM_RATS_M >= 2
    { FTCM_ZETAS_ASM_INIT },
#endif
#if FTCM_RATS_M >= 3
    { FTCM_ZETAS_ASM_INIT },
#endif
#if FTCM_RATS_M >= 4
    { FTCM_ZETAS_ASM_INIT },
#endif
#if FTCM_RATS_M >= 5
    { FTCM_ZETAS_ASM_INIT },
#endif
#if FTCM_RATS_M >= 6
    { FTCM_ZETAS_ASM_INIT },
#endif
#if FTCM_RATS_M >= 7
    { FTCM_ZETAS_ASM_INIT },
#endif
#if FTCM_RATS_M >= 8
    { FTCM_ZETAS_ASM_INIT },
#endif
};

__attribute__((unused)) static int ftcm_ct_memcmp(const uint8_t *a, const uint8_t *b, unsigned n) {
    uint8_t d = 0;
    for (unsigned i = 0; i < n; i++) {
        d |= a[i] ^ b[i];
    }
    return d != 0;
}

#if FTCM_RATS_MODE == 2
/* Keyed polynomial (Carter-Wegman) hash over GF(p), p = 2^31-1, two
 * independent keys -> 62-bit tag.  Sound in the paper's fault model because
 * the faulted contents cannot depend on the secret key: two distinct tables,
 * hashed as 256 16-bit limbs, collide under one key with probability
 * <= 256/(2^31-1) < 2^-23, under both keys < 2^-46 (per fault outcome).  The expected tag is computed by
 * ftcm_rats_init() (in a deployment: at provisioning, stored in OTP).  */
#define P31 0x7fffffffu
static uint32_t ftcm_k1 = 0, ftcm_k2 = 0, ftcm_e1 = 0, ftcm_e2 = 0;
static inline uint32_t mulmod31(uint32_t a, uint32_t b) {
    uint64_t x = (uint64_t)a * b;
    uint32_t s = (uint32_t)(x & P31) + (uint32_t)(x >> 31);
    return (s >= P31) ? s - P31 : s;
}
static void ftcm_uhash(const int32_t *tw, uint32_t *h1, uint32_t *h2) {
    uint32_t a = 0, b = 0;
    for (int i = 0; i < FTCM_TW_WORDS; i++) {
        uint32_t w = (uint32_t)tw[i];
        uint32_t lo = w & 0xffffu, hi = w >> 16;      /* 16-bit limbs < p */
        a = mulmod31(a + lo, ftcm_k1);
        a = mulmod31(a + hi, ftcm_k1);
        b = mulmod31(b + lo, ftcm_k2);
        b = mulmod31(b + hi, ftcm_k2);
    }
    *h1 = a;
    *h2 = b;
}
void ftcm_rats_init(uint32_t k1, uint32_t k2) {
    ftcm_k1 = (k1 % (P31 - 1)) + 1;
    ftcm_k2 = (k2 % (P31 - 1)) + 1;
    ftcm_uhash(ftcm_tw_copies[0], &ftcm_e1, &ftcm_e2);
}
#else
void ftcm_rats_init(uint32_t k1, uint32_t k2) {
    (void)k1;
    (void)k2;
}
#endif

__attribute__((unused)) static void ftcm_tag(uint8_t out[32], const int32_t *tw) {
#if FTCM_RATS_MODE == 2
    (void)out;
    (void)tw;
#elif FTCM_RATS_MODE == 0
    sha256(out, (const uint8_t *)tw, FTCM_TW_WORDS * 4);
#else
    /* HMAC-SHA-256 with a device key (demo key from ftcm_tag.h) */
    static const uint8_t key[32] = { FTCM_HMAC_KEY_INIT };
    uint8_t kpad[64 + FTCM_TW_WORDS * 4];
    uint8_t inner[32];
    for (int i = 0; i < 64; i++) {
        kpad[i] = (uint8_t)((i < 32 ? key[i] : 0) ^ 0x36);
    }
    memcpy(kpad + 64, (const uint8_t *)tw, FTCM_TW_WORDS * 4);
    sha256(inner, kpad, sizeof(kpad));
    uint8_t opad[64 + 32];
    for (int i = 0; i < 64; i++) {
        opad[i] = (uint8_t)((i < 32 ? key[i] : 0) ^ 0x5c);
    }
    memcpy(opad + 64, inner, 32);
    sha256(out, opad, sizeof(opad));
#endif
}

#if FTCM_RATS_MODE != 2
static const uint8_t ftcm_expected_tag[32] = {
#if FTCM_RATS_MODE == 0
    FTCM_TAG_SHA256_INIT
#else
    FTCM_TAG_HMAC_INIT
#endif
};
#endif

const int32_t *ftcm_rats_select_verify(const int32_t *override, unsigned *index) {
    unsigned i = ftcm_rand32() % FTCM_RATS_M;
    const int32_t *p = ftcm_tw_copies[i];
    if (override) {
        p = override;                /* fault simulation: corrupted pointer */
    }
    if (index) {
        *index = i;
    }
#if FTCM_RATS_MODE == 2
    uint32_t h1, h2;
    if (ftcm_k1 == 0) {              /* lazy key setup if not provisioned */
        ftcm_rats_init(ftcm_rand32(), ftcm_rand32());
    }
    ftcm_uhash(p, &h1, &h2);         /* hash exactly the words behind p      */
    if ((h1 ^ ftcm_e1) | (h2 ^ ftcm_e2)) {
        return 0;
    }
#else
    uint8_t tag[32];
    ftcm_tag(tag, p);                /* hash exactly the bytes behind p      */
    if (ftcm_ct_memcmp(tag, ftcm_expected_tag, 32)) {
        return 0;
    }
#endif
    return p;                        /* the SAME pointer value is used by NTT */
}

/* ---------------------------------------------------------------- glue */
extern void ntt_fast(int16_t *, const int32_t *);
extern const int32_t zetas_asm[128];

unsigned ftcm_ntt_checked(int16_t *poly, const int32_t *fault_override) {
    unsigned mask = 0;
    const int32_t *tw;
#if FTCM_RATS
    tw = ftcm_rats_select_verify(fault_override, 0);
    if (tw == 0) {
        mask |= FTCM_DET_RATS;
        tw = fault_override ? fault_override : zetas_asm; /* only for C1/C2 stats */
    }
#else
    tw = fault_override ? fault_override : zetas_asm;
#endif
#if FTCM_C1
    if (ftcm_c1_check(tw, FTCM_C1_T)) {
        mask |= FTCM_DET_C1;
    }
#endif
    if (mask == 0 || FTCM_C2) {
        ntt_fast(poly, tw);
    }
#if FTCM_C2
    if (ftcm_c2_check(poly, FTCM_C2_DMIN)) {
        mask |= FTCM_DET_C2;
    }
#endif
    if (mask) {
        memset(poly, 0, 256 * sizeof(int16_t));   /* never release faulty output */
        ftcm_fault_count++;
    }
    return mask;
}

__attribute__((weak)) void ftcm_on_fault(unsigned mask) {
    (void)mask;
    for (;;) {
        /* halt: a deployment would zeroize secrets and reset the device */
    }
}
