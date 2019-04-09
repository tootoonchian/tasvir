/**
 * @file
 *   tasvir.h
 * @brief
 *   Function prototypes for Tasvir.
 *
 * @author
 *   Amin Tootoonchian
 */

#ifndef TASVIR_SRC_TASVIR_UTILS_H_
#define TASVIR_SRC_TASVIR_UTILS_H_
#pragma once

#include "tasvir.h"

/* time */

#define MS2US (1000)
#define S2US (1000 * MS2US)

static inline uint64_t tasvir_tsc2usec(uint64_t tsc) { return tsc * ttld.ndata->tsc2usec_mult; }
static inline uint64_t tasvir_usec2tsc(uint64_t us) { return us / ttld.ndata->tsc2usec_mult; }
static inline uint64_t tasvir_gettime_us() { return tasvir_tsc2usec(__rdtsc()); }

/* copy/strem */

__attribute__((unused)) static inline void tasvir_memset_stream(void *dst, char c, size_t len) {
    uint8_t *ptr = dst;
    while ((uintptr_t)ptr & 31UL) {
        *ptr = c;
        ptr++;
    }
    __m256i m = _mm256_set1_epi8(c);
    while (len >= 32) {
        _mm256_stream_si256((__m256i *)ptr, m);
        ptr += 32;
        len -= 32;
    }
    while (len-- > 0)
        *ptr++ = c;
}

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

/* misc */

#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define TASVIR_ALIGN_ARG(x) (size_t) TASVIR_ALIGNX(x, sizeof(tasvir_arg_promo_t))

/* formatting/printing */

#ifdef TASVIR_DEBUG_HEXDUMP
static inline void tasvir_hexdump(void *addr, size_t len) {
    uint8_t *b = (uint8_t *)addr;
    size_t i;
    for (i = 0; i < len; i += 4) {
        if (i && i % 32 == 0)
            fprintf(stderr, "\n");
        fprintf(stderr, "%02X%02X%02X%02X ", b[i], b[i + 1], b[i + 2], b[i + 3]);
    }
    fprintf(stderr, "\n");
}
#endif

static inline void tasvir_area2str(const tasvir_area_desc *d, char *buf, size_t buf_size) {
    static const char *tasvir_area_type_str[] = {"invalid", "container", "node", "app"};

    snprintf(
        buf, buf_size,
        "name=%s type=%s len=0x%lx sync_us=%lu/%lu boot_us=%lu nr_areas_max=%lu d=%p pd=%p owner=%p h=%p flags=0x%lx",
        d->name, tasvir_area_type_str[d->type], d->len, d->sync_int_us, d->sync_ext_us, d->boot_us, d->nr_areas_max,
        (void *)d, (void *)d->pd, (void *)d->owner, (void *)d->h, d->h ? d->h->flags_ : 0);
}

static inline void tasvir_nid2str(const tasvir_nid *nid, char *buf, size_t buf_size) {
    ether_format_addr(buf, buf_size, &nid->mac_addr);
}

static inline void tasvir_tid2str(const tasvir_tid *tid, char *buf, size_t buf_size) {
    tasvir_nid2str(&tid->nid, buf, buf_size);
    snprintf(&buf[strlen(buf)], buf_size - strlen(buf), "/i%d,c%d,p%d", tid->idx, tid->core, tid->pid);
}

static inline void tasvir_msg2str(tasvir_msg *m, bool is_src_me, bool is_dst_me, char *buf, size_t buf_size) {
    static const char *tasvir_msg_type_str[] = {"invalid", "memory", "rpc_oneway", "rpc_request", "rpc_reply"};
    char direction;
    char src_str[48];
    char dst_str[48];
    tasvir_tid2str(&m->src_tid, src_str, sizeof(src_str));
    tasvir_tid2str(&m->dst_tid, dst_str, sizeof(dst_str));
    if (is_src_me)
        direction = 'O';
    else if (is_dst_me)
        direction = 'I';
    else
        direction = 'F';
    if (m->type == TASVIR_MSG_TYPE_RPC_RESPONSE || m->type == TASVIR_MSG_TYPE_RPC_REQUEST) {
        tasvir_msg_rpc *mr = (tasvir_msg_rpc *)m;
        /* FIXME: badly insecure */
        tasvir_fn_desc *fnd = &ttld.fn_descs[mr->fid];

        snprintf(buf, buf_size, "%c %s->%s id=%d type=%s d=%s v=%lu f=%s", direction, src_str, dst_str, m->id,
                 tasvir_msg_type_str[m->type], mr->d ? mr->d->name : "root", m->version, fnd->name);
    } else {
        snprintf(buf, buf_size, "%c %s->%s id=%d type=%s", direction, src_str, dst_str, m->id,
                 tasvir_msg_type_str[m->type]);
    }
#ifdef TASVIR_DEBUG_HEXDUMP
    tasvir_hexdump(&m->h.eh, m->h.mbuf.data_len);
#endif
}

#endif /* TASVIR_SRC_TASVIR_UTILS_H_ */
