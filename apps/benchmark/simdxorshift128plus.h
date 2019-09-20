/* from https://github.com/lemire/SIMDxorshift
 * Apache 2 license
 */
#ifndef SIMDXORSHIFT128PLUS_H
#define SIMDXORSHIFT128PLUS_H

#include <stdint.h>// life is short, please use a C99-compliant compiler

#if defined(_MSC_VER)
     /* Microsoft C/C++-compatible compiler */
     #include <intrin.h>
#elif defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
     /* GCC-compatible compiler, targeting x86/x86-64 */
     #include <x86intrin.h>
#elif defined(__GNUC__) && defined(__ARM_NEON__)
     /* GCC-compatible compiler, targeting ARM with NEON */
     #include <arm_neon.h>
#elif defined(__GNUC__) && defined(__IWMMXT__)
     /* GCC-compatible compiler, targeting ARM with WMMX */
     #include <mmintrin.h>
#elif (defined(__GNUC__) || defined(__xlC__)) && (defined(__VEC__) || defined(__ALTIVEC__))
     /* XLC or GCC-compatible compiler, targeting PowerPC with VMX/VSX */
     #include <altivec.h>
#elif defined(__GNUC__) && defined(__SPE__)
     /* GCC-compatible compiler, targeting PowerPC with SPE */
     #include <spe.h>
#endif


/* Keys for scalar xorshift128. Must be non-zero
These are modified by xorshift128plus.
 */
struct avx_xorshift128plus_key_s {
    __m256i part1;
    __m256i part2;
};

typedef struct avx_xorshift128plus_key_s avx_xorshift128plus_key_t;



/**
* You can create a new key like so...
*  avx_xorshift128plus_key_t mykey;
*  avx_xorshift128plus_init(324,4444,&mykey);
*
* This feeds the two integers (324 and 4444) as seeds to the random
* number generator.
*
*  Then you can generate random numbers like so...
*      avx_xorshift128plus(&mykey);
* If your application is threaded, each thread should have its own
* key.
*
*
* The seeds (key1 and key2) should be non-zero. You are responsible for
* checking that they are non-zero.
*/
void avx_xorshift128plus_init(uint64_t key1, uint64_t key2, avx_xorshift128plus_key_t *key);

/*
Return a 256-bit random "number"
*/
__m256i avx_xorshift128plus( avx_xorshift128plus_key_t *key);

/**
* equivalent to skipping 2^64 avx_xorshift128plus() calls
* useful to generate a new key from an existing one (multi-threaded context).
*/
void avx_xorshift128plus_jump(avx_xorshift128plus_key_t * key);

/**
 * Fisher-Yates shuffle, shuffling  "size" 32-bit  values in "storage". You must provide the key for
 * randomness.
 */
void  avx_xorshift128plus_shuffle32(avx_xorshift128plus_key_t *key, uint32_t *storage, uint32_t size);

#if defined(__AVX512F__)

struct avx512_xorshift128plus_key_s {
    __m512i part1;
    __m512i part2;
};

typedef struct avx512_xorshift128plus_key_s avx512_xorshift128plus_key_t;



/**
* You can create a new key like so...
*  avx_xorshift128plus_key_t mykey;
*  avx_xorshift128plus_init(324,4444,&mykey);
*
* This feeds the two integers (324 and 4444) as seeds to the random
* number generator.
*
*  Then you can generate random numbers like so...
*      avx_xorshift128plus(&mykey);
* If your application is threaded, each thread should have its own
* key.
*
*
* The seeds (key1 and key2) should be non-zero. You are responsible for
* checking that they are non-zero.
*/
// void avx512_xorshift128plus_init(uint64_t key1, uint64_t key2, avx512_xorshift128plus_key_t *key);

/*
Return a 256-bit random "number"
*/
// __m512i avx512_xorshift128plus( avx512_xorshift128plus_key_t *key);

#endif
/* .c file */
/* used by xorshift128plus_jump_onkeys */
static void xorshift128plus_onkeys(uint64_t * ps0, uint64_t * ps1) {
	uint64_t s1 = *ps0;
	const uint64_t s0 = *ps1;
	*ps0 = s0;
	s1 ^= s1 << 23; // a
	*ps1 = s1 ^ s0 ^ (s1 >> 18) ^ (s0 >> 5); // b, c
}

/* used by avx_xorshift128plus_init */
static void xorshift128plus_jump_onkeys(uint64_t in1, uint64_t in2,
		uint64_t * output1, uint64_t * output2) {
	/* todo: streamline */
	static const uint64_t JUMP[] = { 0x8a5cd789635d2dff, 0x121fd2155c472f96 };
	uint64_t s0 = 0;
	uint64_t s1 = 0;
	for (unsigned int i = 0; i < sizeof(JUMP) / sizeof(*JUMP); i++)
		for (int b = 0; b < 64; b++) {
			if (JUMP[i] & 1ULL << b) {
				s0 ^= in1;
				s1 ^= in2;
			}
			xorshift128plus_onkeys(&in1, &in2);
		}
	output1[0] = s0;
	output2[0] = s1;
}

void avx_xorshift128plus_init(uint64_t key1, uint64_t key2,
		avx_xorshift128plus_key_t *key) {
	uint64_t S0[4];
	uint64_t S1[4];
	S0[0] = key1;
	S1[0] = key2;
	xorshift128plus_jump_onkeys(*S0, *S1, S0 + 1, S1 + 1);
	xorshift128plus_jump_onkeys(*(S0 + 1), *(S1 + 1), S0 + 2, S1 + 2);
	xorshift128plus_jump_onkeys(*(S0 + 2), *(S1 + 2), S0 + 3, S1 + 3);
	key->part1 = _mm256_loadu_si256((const __m256i *) S0);
	key->part2 = _mm256_loadu_si256((const __m256i *) S1);
}

/*
 Return a 256-bit random "number"
 */
__m256i avx_xorshift128plus(avx_xorshift128plus_key_t *key) {
	__m256i s1 = key->part1;
	const __m256i s0 = key->part2;
	key->part1 = key->part2;
	s1 = _mm256_xor_si256(key->part2, _mm256_slli_epi64(key->part2, 23));
	key->part2 = _mm256_xor_si256(
			_mm256_xor_si256(_mm256_xor_si256(s1, s0),
					_mm256_srli_epi64(s1, 18)), _mm256_srli_epi64(s0, 5));
	return _mm256_add_epi64(key->part2, s0);
}

#if defined(__AVX512F__)

inline void avx512_xorshift128plus_init(uint64_t key1, uint64_t key2,
		avx512_xorshift128plus_key_t *__restrict key) {
	uint64_t S0[8];
	uint64_t S1[8];
	S0[0] = key1;
	S1[0] = key2;

	// todo: fix this so that the init is correct
	// GJ - All elements should now be initialized
	xorshift128plus_jump_onkeys(*S0, *S1, S0 + 1, S1 + 1);
	xorshift128plus_jump_onkeys(*(S0 + 1), *(S1 + 1), S0 + 2, S1 + 2);
	xorshift128plus_jump_onkeys(*(S0 + 2), *(S1 + 2), S0 + 3, S1 + 3);
	xorshift128plus_jump_onkeys(*(S0 + 3), *(S1 + 3), S0 + 4, S1 + 4);
	xorshift128plus_jump_onkeys(*(S0 + 4), *(S1 + 4), S0 + 5, S1 + 5);
	xorshift128plus_jump_onkeys(*(S0 + 5), *(S1 + 5), S0 + 6, S1 + 6);
	xorshift128plus_jump_onkeys(*(S0 + 6), *(S1 + 6), S0 + 7, S1 + 7);


	key->part1 = _mm512_loadu_si512((const __m512i *) S0);
	key->part2 = _mm512_loadu_si512((const __m512i *) S1);
}
/*
 Return a 512-bit random "number"
 */
inline __m512i avx512_xorshift128plus(avx512_xorshift128plus_key_t *__restrict key) {
	__m512i s1 = key->part1;
	const __m512i s0 = key->part2;
	key->part1 = key->part2;
	s1 = _mm512_xor_si512(key->part2, _mm512_slli_epi64(key->part2, 23));
	key->part2 = _mm512_xor_si512(
			_mm512_xor_si512(_mm512_xor_si512(s1, s0),
					_mm512_srli_epi64(s1, 18)), _mm512_srli_epi64(s0, 5));
	return _mm512_add_epi64(key->part2, s0);
}

#endif

/**
 * equivalent to skipping 2^64 avx_xorshift128plus() calls
 * useful to generate a new key from an existing one (multi-threaded context).
 */
void avx_xorshift128plus_jump(avx_xorshift128plus_key_t * key) {
	uint64_t S0[4];
	uint64_t S1[4];
	S0[0] = _mm256_extract_epi64(key->part1, 3);
	S1[0] = _mm256_extract_epi64(key->part2, 3);
	xorshift128plus_jump_onkeys(*S0, *S1, S0, S1);
	xorshift128plus_jump_onkeys(*S0, *S1, S0 + 1, S1 + 1);
	xorshift128plus_jump_onkeys(*(S0 + 1), *(S1 + 1), S0 + 2, S1 + 2);
	xorshift128plus_jump_onkeys(*(S0 + 2), *(S1 + 2), S0 + 3, S1 + 3);
	key->part1 = _mm256_loadu_si256((const __m256i *) S0);
	key->part2 = _mm256_loadu_si256((const __m256i *) S1);
}

/**
 * Given 8 random 32-bit integers in randomvals,
 * derive 8 random 32-bit integers that are less than
 * the 32-bit integers in upperbound using the
 * following heuristic:
 *
 *     ( randomval * upperbound ) >> 32
 *
 * This approach generates a very slight bias (of the order of upperbound/2**32), but
 * in a high performance setting, it is probably quite acceptable, and preferable
 * to branching.
 *
 * Reference : Daniel Lemire, Fast Random Integer Generation in an Interval
 * ACM Transactions on Modeling and Computer Simulation (to appear)
 * https://arxiv.org/abs/1805.10941
 *
 */
static __m256i avx_randombound_epu32(__m256i randomvals, __m256i upperbound) {
	/* four values */
	__m256i evenparts = _mm256_srli_epi64(
			_mm256_mul_epu32(randomvals, upperbound), 32);
	/* four other values */
	__m256i oddparts = _mm256_mul_epu32(_mm256_srli_epi64(randomvals, 32),
			_mm256_srli_epi64(upperbound, 32));
	/* note:shift could be replaced by shuffle */
	/* need to blend the eight values */
	return _mm256_blend_epi32(evenparts, oddparts, 0b10101010);
}

void avx_xorshift128plus_shuffle32(avx_xorshift128plus_key_t *key,
		uint32_t *storage, uint32_t size) {
	uint32_t i;
	uint32_t randomsource[8];
	__m256i interval = _mm256_setr_epi32(size, size - 1, size - 2, size - 3,
			size - 4, size - 5, size - 6, size - 7);
	__m256i R = avx_randombound_epu32(avx_xorshift128plus(key), interval);
	_mm256_storeu_si256((__m256i *) randomsource, R);
	__m256i vec8 = _mm256_set1_epi32(8);
	for (i = size; i > 1;) {
		for (int j = 0; j < 8; ++j) {
			uint32_t nextpos = randomsource[j];
			int tmp = storage[i - 1]; // likely in cache
			int val = storage[nextpos]; // could be costly
			storage[i - 1] = val;
			storage[nextpos] = tmp; // you might have to read this store later
			i--;
		}
		interval = _mm256_sub_epi32(interval, vec8);
		R = avx_randombound_epu32(avx_xorshift128plus(key), interval);
		_mm256_storeu_si256((__m256i *) randomsource, R);
	}
}
#endif
