/**
 * @file
 *   utils.h
 * @brief
 *   Tasvir utilities.
 *
 * @author
 *   Amin Tootoonchian
 */

#ifndef TASVIR_UTILS_H_
#define TASVIR_UTILS_H_
#pragma once

#include <immintrin.h>
#include <rte_cycles.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __AVX512F__
#define TASVIR_VEC_BYTES 64
#elif __AVX2__
#define TASVIR_VEC_BYTES 32
#elif __AVX__
#define TASVIR_VEC_BYTES 16
#else
#error AVX support required
#endif

static inline void tasvir_store_vec(void *__restrict dst, const void *__restrict src) {
    dst = __builtin_assume_aligned(dst, TASVIR_VEC_BYTES);
    src = __builtin_assume_aligned(src, TASVIR_VEC_BYTES);
#ifdef __AVX512F__
    _mm512_store_si512((__m512i *)dst, _mm512_load_si512((__m512i *)src));
#elif __AVX2__
    _mm256_store_si256((__m256i *)dst, _mm256_load_si256((__m256i *)src));
#elif __AVX__
    _mm_store_si128((__m128i *)dst, _mm_load_si128((__m128i *)src));
#endif
}

static inline void tasvir_stream_vec(void *__restrict dst, const void *__restrict src) {
    dst = __builtin_assume_aligned(dst, TASVIR_VEC_BYTES);
    src = __builtin_assume_aligned(src, TASVIR_VEC_BYTES);
#ifdef __AVX512F__
    _mm512_stream_si512((__m512i *)dst, _mm512_stream_load_si512((__m512i *)src));
#elif __AVX2__
    _mm256_stream_si256((__m256i *)dst, _mm256_stream_load_si256((__m256i *)src));
#elif __AVX__
    _mm_stream_si128((__m128i *)dst, _mm_stream_load_si128((__m128i *)src));
#endif
}

static inline void tasvir_store_vec_rep(void *__restrict dst, const void *__restrict src, size_t len) {
    dst = __builtin_assume_aligned(dst, TASVIR_VEC_BYTES);
    src = __builtin_assume_aligned(src, TASVIR_VEC_BYTES);
    void *dst_end = (void *)((uintptr_t)dst + len);
    do {
        tasvir_store_vec(dst, src);
        dst = (uint8_t *)dst + TASVIR_VEC_BYTES;
        src = (uint8_t *)src + TASVIR_VEC_BYTES;
    } while (dst < dst_end);
}

static inline void tasvir_stream_vec_rep(void *__restrict dst, const void *__restrict src, size_t len) {
    dst = __builtin_assume_aligned(dst, TASVIR_VEC_BYTES);
    src = __builtin_assume_aligned(src, TASVIR_VEC_BYTES);
    void *dst_end = (void *)((uintptr_t)dst + len);
    do {
        tasvir_stream_vec(dst, src);
        dst = (uint8_t *)dst + TASVIR_VEC_BYTES;
        src = (uint8_t *)src + TASVIR_VEC_BYTES;
    } while (dst < dst_end);
}

#ifdef __cplusplus
}
#endif
#endif /* TASVIR_UTILS_H_ */
