/*
 * ftcm.h -- Fault-resilient Twiddle CounterMeasures for the pqm4
 *           ML-KEM m4fspeed NTT (Plantard-form 32-bit twiddle table).
 *
 * Compile-time configuration (set in ftcm_config.h, generated per variant):
 *   FTCM_C1      1 = twiddle sanity verification (representation-aware)
 *   FTCM_C1_T    number of sampled entries (default 4)
 *   FTCM_C2      1 = output validation (distinct-value proxy of entropy)
 *   FTCM_C2_DMIN abort if fewer than this many distinct coefficients (128)
 *   FTCM_RATS    1 = RATS: m identical copies, random selection, tag check
 *   FTCM_RATS_M  number of copies (default 4)
 *   FTCM_RATS_MODE 0 = keyless SHA-256, 1 = HMAC-SHA-256,
 *                  2 = keyed polynomial universal hash (62-bit tag)
 */
#ifndef FTCM_H
#define FTCM_H
#include <stdint.h>
#include "ftcm_config.h"

#ifndef FTCM_C1
#define FTCM_C1 0
#endif
#ifndef FTCM_C1_T
#define FTCM_C1_T 4
#endif
#ifndef FTCM_C2
#define FTCM_C2 0
#endif
#ifndef FTCM_C2_DMIN
#define FTCM_C2_DMIN 128
#endif
#ifndef FTCM_RATS
#define FTCM_RATS 0
#endif
#ifndef FTCM_RATS_M
#define FTCM_RATS_M 4
#endif
#ifndef FTCM_RATS_MODE
#define FTCM_RATS_MODE 0
#endif

#define FTCM_DET_C1   1u
#define FTCM_DET_C2   2u
#define FTCM_DET_RATS 4u

/* number of 32-bit twiddle words consumed by ntt_fast (index 127 is padding) */
#define FTCM_TW_USED 127
#define FTCM_TW_WORDS 128

/* Representation-aware C1 for Plantard words: returns 1 if the table fails. */
int ftcm_c1_check(const int32_t *tw, unsigned t);
/* C2 proxy: returns 1 if the NTT output has fewer than dmin distinct values. */
int ftcm_c2_check(const int16_t *poly, unsigned dmin);
/* RATS: select a random copy, authenticate the bytes fetched through the
 * selected pointer, return that pointer (or NULL on tag mismatch).
 * If `override` != NULL the fetch pointer is replaced by it (fault simulation:
 * models a corrupted pointer register).  *index receives the selected copy. */
const int32_t *ftcm_rats_select_verify(const int32_t *override, unsigned *index);
/* Full protected NTT: returns a bitmask of detections (0 = clean).
 * On detection the output polynomial is zeroized and must not be used. */
unsigned ftcm_ntt_checked(int16_t *poly, const int32_t *fault_override);
/* Called by ntt() when ftcm_ntt_checked reports a detection. Weak; the default
 * implementation halts (a deployment would zeroize secrets and reset). */
void ftcm_on_fault(unsigned mask);

uint32_t ftcm_rand32(void);
/* RATS mode 2 only: set the two hash keys and compute the reference tag */
void ftcm_rats_init(uint32_t k1, uint32_t k2);
extern volatile unsigned ftcm_fault_count;

/* genuine table copies used by RATS (FTCM_RATS_M identical copies in flash) */
extern const int32_t ftcm_tw_copies[FTCM_RATS_M][FTCM_TW_WORDS];

/* "verify-what-you-use" alternative (TOCTOU-resistant), reference C NTT with
 * an inline polynomial hash over the twiddles as they are consumed.  */
void ftcm_ntt_ref(int16_t r[256]);
int  ftcm_ntt_ref_inline(int16_t r[256], const int16_t *zetas_ptr);
void ftcm_inline_init(uint32_t key);
extern const int16_t ftcm_zetas_ref[128];
#endif
