#ifndef TASVIR_SRC_TASVIR_UTILS_H_
#define TASVIR_SRC_TASVIR_UTILS_H_
#pragma once

#include <immintrin.h>
#include <netinet/ether.h>

#include "tasvir.h"

/* logging */

#define RED "\x1B[31m"
#define GRN "\x1B[32m"
#define YEL "\x1B[33m"
#define BLU "\x1B[34m"
#define MAG "\x1B[35m"
#define CYN "\x1B[36m"
#define WHT "\x1B[37m"
#define RESET "\x1B[0m"

#define LOG_COLORS(MSG_CLR, FMT, ...)                                                                           \
    {                                                                                                           \
        fprintf(stderr, GRN "%16.3f " CYN "%-22.22s " MSG_CLR FMT "\n" RESET,                                   \
                ttld.ndata ? (ttld.ndata->time_us - ttld.ndata->boot_us) / 1000. : 0, __func__, ##__VA_ARGS__); \
    }

#define UNUSED __attribute__((unused))

#ifndef TASVIR_LOG_LEVEL
#define TASVIR_LOG_LEVEL 7
#endif

#if TASVIR_LOG_LEVEL >= 7
#define TASVIR_DEBUG
#define LOG_DBG(FMT, ...) LOG_COLORS(WHT, FMT, ##__VA_ARGS__)
#else
#define LOG_DBG(FMT, ...) \
    do {                  \
    } while (0)
#endif
#if TASVIR_LOG_LEVEL >= 6
#define LOG_VERBOSE(FMT, ...) LOG_COLORS(WHT, FMT, ##__VA_ARGS__)
#else
#define LOG_VERBOSE(FMT, ...) \
    do {                      \
    } while (0)
#endif
#if TASVIR_LOG_LEVEL >= 4
#define LOG_INFO(FMT, ...) LOG_COLORS(YEL, FMT, ##__VA_ARGS__)
#else
#define LOG_INFO(FMT, ...) \
    do {                   \
    } while (0)
#endif
#if TASVIR_LOG_LEVEL >= 3
#define LOG_WARN(FMT, ...) LOG_COLORS(YEL, FMT, ##__VA_ARGS__)
#else
#define LOG_WARN(FMT, ...) \
    do {                   \
    } while (0)
#endif
#if TASVIR_LOG_LEVEL >= 2
#define LOG_ERR(FMT, ...) LOG_COLORS(RED, FMT, ##__VA_ARGS__)
#else
#define LOG_ERR(FMT, ...) \
    do {                  \
    } while (0)
#endif
#if TASVIR_LOG_LEVEL >= 1
#define LOG_FATAL(FMT, ...) LOG_COLORS(RED, FMT, ##__VA_ARGS__)
#else
#define LOG_FATAL(FMT, ...) \
    do {                    \
    } while (0)
#endif

/* time */

#define MS2US (1000)
#define S2US (1000 * MS2US)
#define KB (1000)
#define MB (1000 * KB)
#define GB (1000 * MB)

static inline uint64_t tasvir_tsc2usec(uint64_t tsc) { return tsc * ttld.tsc2usec_mult; }
static inline uint64_t tasvir_usec2tsc(uint64_t us) { return us / ttld.tsc2usec_mult; }
static inline uint64_t tasvir_time_us() { return tasvir_tsc2usec(__rdtsc()); }
static inline uint64_t tasvir_time_boot_us() { return tasvir_tsc2usec(__rdtsc()) - ttld.ndata->boot_us; }

/* area */

bool tasvir_area_is_active(const tasvir_area_desc *d);
bool tasvir_area_is_local(const tasvir_area_desc *d);
bool tasvir_area_is_mapped_rw(const tasvir_area_desc *d);
typedef size_t (*tasvir_fnptr_walkcb)(tasvir_area_desc *);
size_t tasvir_area_walk(tasvir_area_desc *d, tasvir_fnptr_walkcb fnptr);

/* memory map */

static inline tasvir_log_t *tasvir_data2log(void *data) {
    return (tasvir_log_t *)TASVIR_ADDR_LOG +
           _pext_u64((uintptr_t)data, (TASVIR_SIZE_DATA - 1) & (~0UL << TASVIR_SHIFT_UNIT));
}
static inline void *tasvir_data2ro(void *data) { return (uint8_t *)data + TASVIR_OFFSET_RO; }
static inline void *tasvir_data2rw(void *data) { return (uint8_t *)data + TASVIR_OFFSET_RW; }
void tasvir_update_va(const tasvir_area_desc *d, bool is_rw);

/* memory copy/strem */

#ifdef __AVX512F__
#define TASVIR_VEC_BYTES 64
#elif __AVX2__
#define TASVIR_VEC_BYTES 32
#elif __AVX__
#define TASVIR_VEC_BYTES 16
#else
#error AVX support required
#endif

static inline void tasvir_memset_stream(void *dst, char c, size_t len) {
    uint8_t *ptr = dst;
#ifdef __AVX512F__
    __m512i m = _mm512_set1_epi8(c);
#elif __AVX2__
    __m256i m = _mm256_set1_epi8(c);
#elif __AVX__
    __m128i m = _mm_set1_epi8(c);
#endif
    while ((uintptr_t)ptr & (TASVIR_VEC_BYTES - 1)) {
        *ptr = c;
        ptr++;
    }
    while (len >= TASVIR_VEC_BYTES) {
#ifdef __AVX512F__
        _mm512_stream_si512((__m512i *)ptr, m);
#elif __AVX2__
        _mm256_stream_si256((__m256i *)ptr, m);
#elif __AVX__
        _mm_stream_si128((__m128i *)ptr, m);
#endif
        ptr += TASVIR_VEC_BYTES;
        len -= TASVIR_VEC_BYTES;
    }
    while (len-- > 0)
        *ptr++ = c;
}

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
    // _mm_cldemote(dst); // wish we had cldemote here :-)
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

/* thread */

static inline bool tasvir_is_booting() { return !ttld.thread || (ttld.tdata->state == TASVIR_THREAD_STATE_BOOTING); }

static inline bool tasvir_is_running() { return ttld.thread && (ttld.tdata->state == TASVIR_THREAD_STATE_RUNNING); }

static inline bool tasvir_thread_is_local(tasvir_thread *t) {
    return memcmp(&t->tid.nid, &ttld.ndata->boot_tid.nid, sizeof(tasvir_nid)) == 0;
}

/* net */

static inline void tasvir_populate_msg_nethdr(tasvir_msg *m) {
    m->mbuf.refcnt = 1;
    m->mbuf.nb_segs = 1;
    memcpy(m->eh.ether_dhost, &m->dst_tid.nid.mac_addr, ETH_ALEN);
    memcpy(m->eh.ether_shost, &ttld.ndata->mac_addr, ETH_ALEN);
    m->eh.ether_type = rte_cpu_to_be_16(TASVIR_ETH_PROTO);

    // FIXME: not all will be sent out
    ttld.ndata->stats_cur.tx_bytes += m->mbuf.pkt_len;
    ttld.ndata->stats_cur.tx_pkts++;
}

/* formatting/printing */

void tasvir_hexdump(void *addr, size_t len);
void tasvir_area_str(const tasvir_area_desc *d, char *buf, size_t buf_size);
void tasvir_msg_str(tasvir_msg *m, bool is_src_me, bool is_dst_me, char *buf, size_t buf_size);
void tasvir_nid_str(const tasvir_nid *nid, char *buf, size_t buf_size);
void tasvir_tid_str(const tasvir_tid *tid, char *buf, size_t buf_size);
void tasvir_print_views(const tasvir_node *);

/* misc */

#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define MAX(x, y) ((x) > (y) ? (x) : (y))

#endif /* TASVIR_SRC_TASVIR_UTILS_H_ */
