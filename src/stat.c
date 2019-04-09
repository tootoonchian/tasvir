#include "tasvir.h"

tasvir_stats tasvir_stats_get() {
    ttld.ndata->stat_update_req = 1;
    // assuming 1ms is enough for daemon to run service once
    rte_delay_us_block(1000);
    return ttld.ndata->stats;
}

void tasvir_stats_reset() {
    ttld.ndata->stat_reset_req = 1;
    while (ttld.ndata->stat_reset_req != 0)
        _mm_pause();
}

#ifdef TASVIR_DAEMON
void tasvir_stats_update() {
    uint64_t MS = 1 * 1000;  // in us
    uint64_t S = MS * 1000;  // in us
    uint64_t interval_us = ttld.ndata->time_us - ttld.ndata->last_stat;
    ttld.ndata->last_stat = ttld.ndata->time_us;
    tasvir_stats *cur = &ttld.ndata->stats_cur;
    tasvir_stats *avg = &ttld.ndata->stats;

    struct rte_eth_stats s;
    rte_eth_stats_get(0, &s);

    LOG_INFO(
        "sync=+%lu/s,-%lu/s sync_t=%.1f%%,%luus/sync changed=%luKB/s,%luKB/sync processed=%luKB/s,%luKB/sync "
        "\n                                        "
        "rx=%luKB/s,%luKpps tx=%luKB/s,%luKpps "
        "(ipkts=%lu ibytes=%lu ierr=%lu imiss=%lu inombuf=%lu"
        ",opkts=%lu obytes=%lu oerr=%lu)",
        S * cur->success / interval_us, S * cur->failure / interval_us, 100. * cur->sync_us / interval_us,
        cur->success > 0 ? cur->sync_us / cur->success : 0, MS * cur->sync_changed_bytes / interval_us,
        cur->success > 0 ? cur->sync_changed_bytes / 1000 / cur->success : 0,
        MS * cur->sync_processed_bytes / interval_us,
        cur->success > 0 ? cur->sync_processed_bytes / 1000 / cur->success : 0, MS * cur->rx_bytes / interval_us,
        MS * cur->rx_pkts / interval_us, MS * cur->tx_bytes / interval_us, MS * cur->tx_pkts / interval_us, s.ipackets,
        s.ibytes, s.ierrors, s.imissed, s.rx_nombuf, s.opackets, s.obytes, s.oerrors);

    avg->success += cur->success;
    avg->failure += cur->failure;
    avg->sync_barrier_us += cur->sync_barrier_us;
    avg->sync_us += cur->sync_us;
    avg->sync_changed_bytes += cur->sync_changed_bytes;
    avg->sync_processed_bytes += cur->sync_processed_bytes;
    avg->rx_bytes += cur->rx_bytes;
    avg->rx_pkts += cur->rx_pkts;
    avg->tx_bytes += cur->rx_bytes;
    avg->tx_pkts += cur->rx_pkts;

    memset(cur, 0, sizeof(*cur));
    // tasvir_area_walk(ttld.root_desc, &tasvir_print_area);
}
#endif
