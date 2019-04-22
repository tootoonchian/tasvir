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

#ifdef __cplusplus
}
#endif
#endif /* TASVIR_UTILS_H_ */
