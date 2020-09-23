#include "aes-kw.h"

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC target("ssse3")
#pragma GCC target("aes")
#endif

#include <immintrin.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if aes_kw_KEYBYTES == 16
#define AES_ROUNDS 10
#elif aes_kw_KEYBYTES == 32
#define AES_ROUNDS 14
#else
#error Unsupported key size
#endif

#define FEISTEL_ROUNDS 5

#ifndef CRYPTO_ALIGN
#if defined(__INTEL_COMPILER) || defined(_MSC_VER)
#define CRYPTO_ALIGN(x) __declspec(align(x))
#elif defined(__GNUC__) || defined(__clang__)
#define CRYPTO_ALIGN(x) __attribute__((aligned(x)))
#else
#define CRYPTO_ALIGN(x)
#endif
#endif

static inline void
store32_be(unsigned char dst[4], uint32_t w)
{
    int i;

    for (i = 3; i != 0; i--) {
        dst[i] = (unsigned char) w;
        w >>= 8;
    }
    dst[i] = (unsigned char) w;
}

static inline uint64_t
load64_be(const unsigned char src[4])
{
    uint64_t w = 0;
    int      i;

    w = src[0];
    for (i = 1; i < 8; i++) {
        w = (w << 8) | src[i];
    }
    return w;
}

static inline void
store64_be(unsigned char dst[4], uint64_t w)
{
    int i;

    for (i = 7; i != 0; i--) {
        dst[i] = (unsigned char) w;
        w >>= 8;
    }
    dst[i] = (unsigned char) w;
}

#define DRC(ROUND, RC)                                                     \
    do {                                                                   \
        s                 = _mm_aeskeygenassist_si128(t1, (RC));           \
        round_keys[ROUND] = t1;                                            \
        t1                = _mm_xor_si128(t1, _mm_slli_si128(t1, 4));      \
        t1                = _mm_xor_si128(t1, _mm_slli_si128(t1, 8));      \
        t1                = _mm_xor_si128(t1, _mm_shuffle_epi32(s, 0xff)); \
    } while (0)

#define DRC1(ROUND, RC)                                                    \
    do {                                                                   \
        s                 = _mm_aeskeygenassist_si128(t2, (RC));           \
        round_keys[ROUND] = t2;                                            \
        t1                = _mm_xor_si128(t1, _mm_slli_si128(t1, 4));      \
        t1                = _mm_xor_si128(t1, _mm_slli_si128(t1, 8));      \
        t1                = _mm_xor_si128(t1, _mm_shuffle_epi32(s, 0xff)); \
    } while (0)

#define DRC2(ROUND, RC)                                                    \
    do {                                                                   \
        s                 = _mm_aeskeygenassist_si128(t1, (RC));           \
        round_keys[ROUND] = t1;                                            \
        t2                = _mm_xor_si128(t2, _mm_slli_si128(t2, 4));      \
        t2                = _mm_xor_si128(t2, _mm_slli_si128(t2, 8));      \
        t2                = _mm_xor_si128(t2, _mm_shuffle_epi32(s, 0xaa)); \
    } while (0)

#if AES_ROUNDS == 10
static void
_aes_key_expand_128(__m128i round_keys[AES_ROUNDS + 1], __m128i t1)
{
    __m128i s;

    DRC(0, 1);
    DRC(1, 2);
    DRC(2, 4);
    DRC(3, 8);
    DRC(4, 16);
    DRC(5, 32);
    DRC(6, 64);
    DRC(7, 128);
    DRC(8, 27);
    DRC(9, 54);
    round_keys[10] = t1;
}

#define COMPUTE_AES_ROUNDS(IN)                                                   \
    do {                                                                         \
        r = _mm_aesenc_si128(_mm_xor_si128((IN), round_keys[0]), round_keys[1]); \
        r = _mm_aesenc_si128(_mm_aesenc_si128(r, round_keys[2]), round_keys[3]); \
        r = _mm_aesenc_si128(_mm_aesenc_si128(r, round_keys[4]), round_keys[5]); \
        r = _mm_aesenc_si128(_mm_aesenc_si128(r, round_keys[6]), round_keys[7]); \
        r = _mm_aesenc_si128(_mm_aesenc_si128(r, round_keys[8]), round_keys[9]); \
        r = _mm_aesenclast_si128(r, round_keys[10]);                             \
    } while (0)

#define COMPUTE_AES_DEC_ROUNDS(IN)                                                       \
    do {                                                                                 \
        r = _mm_aesdec_si128(_mm_xor_si128((IN), inv_round_keys[0]), inv_round_keys[1]); \
        r = _mm_aesdec_si128(_mm_aesdec_si128(r, inv_round_keys[2]), inv_round_keys[3]); \
        r = _mm_aesdec_si128(_mm_aesdec_si128(r, inv_round_keys[4]), inv_round_keys[5]); \
        r = _mm_aesdec_si128(_mm_aesdec_si128(r, inv_round_keys[6]), inv_round_keys[7]); \
        r = _mm_aesdec_si128(_mm_aesdec_si128(r, inv_round_keys[8]), inv_round_keys[9]); \
        r = _mm_aesdeclast_si128(r, inv_round_keys[10]);                                 \
    } while (0)

#elif AES_ROUNDS == 14

static void
_aes_key_expand_256(__m128i round_keys[AES_ROUNDS + 1], __m128i t1, __m128i t2)
{
    __m128i s;

    round_keys[0] = t1;
    DRC1(1, 1);
    DRC2(2, 1);
    DRC1(3, 2);
    DRC2(4, 2);
    DRC1(5, 4);
    DRC2(6, 4);
    DRC1(7, 8);
    DRC2(8, 8);
    DRC1(9, 16);
    DRC2(10, 16);
    DRC1(11, 32);
    DRC2(12, 32);
    DRC1(13, 64);
    round_keys[14] = t1;
}

#define COMPUTE_AES_ROUNDS(IN)                                                     \
    do {                                                                           \
        r = _mm_aesenc_si128(_mm_xor_si128((IN), round_keys[0]), round_keys[1]);   \
        r = _mm_aesenc_si128(_mm_aesenc_si128(r, round_keys[2]), round_keys[3]);   \
        r = _mm_aesenc_si128(_mm_aesenc_si128(r, round_keys[4]), round_keys[5]);   \
        r = _mm_aesenc_si128(_mm_aesenc_si128(r, round_keys[6]), round_keys[7]);   \
        r = _mm_aesenc_si128(_mm_aesenc_si128(r, round_keys[8]), round_keys[9]);   \
        r = _mm_aesenc_si128(_mm_aesenc_si128(r, round_keys[10]), round_keys[11]); \
        r = _mm_aesenc_si128(_mm_aesenc_si128(r, round_keys[12]), round_keys[13]); \
        r = _mm_aesenclast_si128(r, round_keys[14]);                               \
    } while (0)

#define COMPUTE_AES_DEC_ROUNDS(IN)                                                         \
    do {                                                                                   \
        r = _mm_aesdec_si128(_mm_xor_si128((IN), inv_round_keys[0]), inv_round_keys[1]);   \
        r = _mm_aesdec_si128(_mm_aesdec_si128(r, inv_round_keys[2]), inv_round_keys[3]);   \
        r = _mm_aesdec_si128(_mm_aesdec_si128(r, inv_round_keys[4]), inv_round_keys[5]);   \
        r = _mm_aesdec_si128(_mm_aesdec_si128(r, inv_round_keys[6]), inv_round_keys[7]);   \
        r = _mm_aesdec_si128(_mm_aesdec_si128(r, inv_round_keys[8]), inv_round_keys[9]);   \
        r = _mm_aesdec_si128(_mm_aesdec_si128(r, inv_round_keys[10]), inv_round_keys[11]); \
        r = _mm_aesdec_si128(_mm_aesdec_si128(r, inv_round_keys[12]), inv_round_keys[13]); \
        r = _mm_aesdeclast_si128(r, inv_round_keys[14]);                                   \
    } while (0)

#endif

static void
key_expand(__m128i *round_keys, const unsigned char *key)
{
#if AES_ROUNDS == 10
    _aes_key_expand_128(round_keys, _mm_loadu_si128((const __m128i *) (const void *) key));
#elif AES_ROUNDS == 14
    _aes_key_expand_256(round_keys, _mm_loadu_si128((const __m128i *) (const void *) key),
                        _mm_loadu_si128((const __m128i *) (const void *) (key + 16)));
#endif
}

static inline void
invert_round_keys(__m128i inv_round_keys[AES_ROUNDS + 1], const __m128i round_keys[AES_ROUNDS + 1])
{
    int i;

    inv_round_keys[0] = round_keys[AES_ROUNDS];
    for (i = 1; i < AES_ROUNDS; i++) {
        inv_round_keys[i] = _mm_aesimc_si128(round_keys[AES_ROUNDS - i]);
    }
    inv_round_keys[AES_ROUNDS] = round_keys[0];
}

static void
inv_key_expand(__m128i *inv_round_keys, const unsigned char *key)
{
    __m128i round_keys[AES_ROUNDS + 1];

#if AES_ROUNDS == 10
    _aes_key_expand_128(round_keys, _mm_loadu_si128((const __m128i *) (const void *) key));
#elif AES_ROUNDS == 14
    _aes_key_expand_256(round_keys, _mm_loadu_si128((const __m128i *) (const void *) key),
                        _mm_loadu_si128((const __m128i *) (const void *) (key + 16)));
#endif
    invert_round_keys(inv_round_keys, round_keys);
}

int
aes_kw_wrap(unsigned char *padded_out, size_t padded_out_len, const unsigned char *in,
            size_t in_len, const unsigned char key[aes_kw_KEYBYTES])
{
    __m128i                        round_keys[AES_ROUNDS + 1];
    __m128i                        r;
    CRYPTO_ALIGN(16) unsigned char block[16]  = { 0 };
    unsigned char                  aiv[8]     = { 0xA6, 0x59, 0x59, 0xA6, 0, 0, 0, 0 };
    unsigned char                  counter[8] = { 0 };
    size_t                         i;
    int                            j, k;

    if ((padded_out_len & 7) != 0 || padded_out_len <= in_len || padded_out_len - in_len < 8) {
        return -1;
    }
    if (in_len > (uint32_t) -1 || in_len >= (uint64_t) -1 / FEISTEL_ROUNDS) {
        return -1;
    }
    store32_be(aiv + 4, (uint32_t) in_len);
    memcpy(block, aiv, 8);

    key_expand(round_keys, key);
    if (in_len == 8) {
        memcpy(block + 8, in, 8);
        COMPUTE_AES_ROUNDS(_mm_loadu_si128((const __m128i *) (const void *) block));
        _mm_storeu_si128((__m128i *) (void *) padded_out, r);
        return 0;
    }

    memset(padded_out, 0, padded_out_len);
    memcpy(padded_out + 8, in, in_len);
    for (j = 0; j < FEISTEL_ROUNDS; j++) {
        for (i = 8; i <= ((in_len + 7) & ~7U); i += 8) {
            memcpy(block + 8, padded_out + i, 8);
            COMPUTE_AES_ROUNDS(_mm_loadu_si128((const __m128i *) (const void *) block));
            _mm_storeu_si128((__m128i *) (void *) block, r);
            store64_be(counter, load64_be(counter) + 1);
            for (k = 0; k < 8; k++) {
                block[8 + k] ^= counter[k];
            }
            memcpy(padded_out + i, block + 8, 8);
        }
    }
    memcpy(padded_out, block, 8);

    return 0;
}

int
aes_kw_unwrap(unsigned char *out, size_t out_len, size_t padded_out_len,
              const unsigned char *padded_in, size_t padded_in_len,
              const unsigned char key[aes_kw_KEYBYTES])
{
    __m128i                        inv_round_keys[AES_ROUNDS + 1];
    __m128i                        r;
    CRYPTO_ALIGN(16) unsigned char block[16]  = { 0 };
    unsigned char                  aiv[8]     = { 0xA6, 0x59, 0x59, 0xA6, 0, 0, 0, 0 };
    unsigned char                  counter[8] = { 0 };
    size_t                         i;
    int                            j, k;

    if (padded_in_len < 8 || (padded_in_len & 7) != 0 || (padded_out_len & 7) != 0 ||
        padded_out_len < padded_in_len - 8 || out_len < padded_out_len) {
        return -1;
    }
    if (out_len > (uint32_t) -1 || out_len >= (uint64_t) -1 / FEISTEL_ROUNDS) {
        return -1;
    }
    store32_be(aiv + 4, (uint32_t) out_len);

    inv_key_expand(inv_round_keys, key);
    if (out_len == 8) {
        COMPUTE_AES_DEC_ROUNDS(_mm_loadu_si128((const __m128i *) (const void *) padded_in));
        _mm_storeu_si128((__m128i *) (void *) block, r);
        if (memcmp(block, aiv, 8) != 0) {
            memset(out, 0xd0, 8);
            return -1;
        }
        memcpy(out, block + 8, 8);
        return 0;
    }

    memcpy(out, padded_in + 8, padded_out_len);
    memcpy(block, padded_in, 8);
    store64_be(counter, FEISTEL_ROUNDS * padded_out_len / 8);
    for (j = 0; j < FEISTEL_ROUNDS; j++) {
        i = padded_out_len;
        while (i >= 8) {
            i -= 8;
            memcpy(block + 8, out + i, 8);
            for (k = 0; k < 8; k++) {
                block[8 + k] ^= counter[k];
            }
            store64_be(counter, load64_be(counter) - 1);
            COMPUTE_AES_DEC_ROUNDS(_mm_loadu_si128((const __m128i *) (const void *) block));
            _mm_storeu_si128((__m128i *) (void *) block, r);
            memcpy(out + i, block + 8, 8);
        }
    }
    if (memcmp(block, aiv, 8) != 0) {
        memset(out, 0xd0, padded_out_len);
        return -1;
    }
    return 0;
}
