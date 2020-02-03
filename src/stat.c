#include <rte_ethdev.h>

#include "tasvir.h"

tasvir_stats tasvir_stats_get() {
    ttld.ndata->stat_update_req = true;
    while (ttld.ndata->stat_update_req)
        _mm_pause();
    return ttld.ndata->stats;
}

void tasvir_stats_reset() {
#ifdef TASVIR_DAEMON
    memset(&ttld.ndata->stats, 0, sizeof(tasvir_stats));
    memset(&ttld.ndata->stats_cur, 0, sizeof(tasvir_stats));
    ttld.ndata->last_stat = ttld.ndata->time_us;
    ttld.ndata->last_sync_int_start = ttld.ndata->time_us;
    ttld.ndata->last_sync_ext_start = ttld.ndata->time_us;
    ttld.ndata->last_sync_int_end = ttld.ndata->time_us;
    ttld.ndata->last_sync_ext_end = ttld.ndata->time_us;
    ttld.ndata->stat_reset_req = false;
#else
    ttld.ndata->stat_reset_req = true;
    while (ttld.ndata->stat_reset_req)
        _mm_pause();
#endif
}

#ifdef TASVIR_DAEMON
void tasvir_stats_update() {
    uint64_t interval_us = ttld.ndata->time_us - ttld.ndata->last_stat;
    if (!interval_us)
        return;
    ttld.ndata->last_stat = ttld.ndata->time_us;
    tasvir_stats *cur = &ttld.ndata->stats_cur;
    tasvir_stats *avg = &ttld.ndata->stats;

    struct rte_eth_stats s;
    rte_eth_stats_get(0, &s);

    avg->isync_success += cur->isync_success;
    avg->isync_failure += cur->isync_failure;
    avg->isync_barrier_us += cur->isync_barrier_us;
    avg->isync_us += cur->isync_us;
    avg->isync_changed_bytes += cur->isync_changed_bytes;
    avg->isync_processed_bytes += cur->isync_processed_bytes;
    avg->esync_cnt += cur->esync_cnt;
    avg->esync_us += cur->esync_us;
    avg->esync_changed_bytes += cur->esync_changed_bytes;
    avg->esync_processed_bytes += cur->esync_processed_bytes;
    avg->rx_bytes += cur->rx_bytes;
    avg->rx_pkts += cur->rx_pkts;
    avg->tx_bytes += cur->rx_bytes;
    avg->tx_pkts += cur->rx_pkts;

    LOG_INFO(
        "isync_cnt=+%lu/s,-%lu/s isync_t=%.1f%%,%luus/call "
        "isync_changed=%luKB/s,%luKB/call isync_processed=%luKB/s,%luKB/call",
        S2US * cur->isync_success / interval_us, S2US * cur->isync_failure / interval_us,
        100. * cur->isync_us / interval_us, cur->isync_success > 0 ? cur->isync_us / cur->isync_success : 0,
        MS2US * cur->isync_changed_bytes / interval_us,
        cur->isync_success > 0 ? cur->isync_changed_bytes / 1000 / cur->isync_success : 0,
        MS2US * cur->isync_processed_bytes / interval_us,
        cur->isync_success > 0 ? cur->isync_processed_bytes / 1000 / cur->isync_success : 0);
    LOG_INFO(
        "esync_cnt=%lu/s esync_t=%.1f%%,%luus/call "
        "esync_changed=%luKB/s,%luKB/call esync_processed=%luKB/s,%luKB/call",
        S2US * cur->esync_cnt / interval_us, 100. * cur->esync_us / interval_us,
        cur->esync_cnt > 0 ? cur->esync_us / cur->esync_cnt : 0, MS2US * cur->esync_changed_bytes / interval_us,
        cur->esync_cnt > 0 ? cur->esync_changed_bytes / 1000 / cur->esync_cnt : 0,
        MS2US * cur->esync_processed_bytes / interval_us,
        cur->esync_cnt > 0 ? cur->esync_processed_bytes / 1000 / cur->esync_cnt : 0);
    LOG_INFO(
        "rx=%luKB/s,%luKpps tx=%luKB/s,%luKpps "
        "ipkts=%lu ibytes=%lu ierr=%lu imiss=%lu inombuf=%lu opkts=%lu obytes=%lu oerr=%lu",
        MS2US * cur->rx_bytes / interval_us, MS2US * cur->rx_pkts / interval_us, MS2US * cur->tx_bytes / interval_us,
        MS2US * cur->tx_pkts / interval_us, s.ipackets, s.ibytes, s.ierrors, s.imissed, s.rx_nombuf, s.opackets,
        s.obytes, s.oerrors);

    memset(cur, 0, sizeof(*cur));
    ttld.ndata->stat_update_req = false;
}
#endif
