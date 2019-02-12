#include "tasvir.h"

tasvir_stats tasvir_stats_get() {
    ttld.ndata->stat_update_req = 1;
    // assuming 1ms is enough for daemon to run service once
    rte_delay_us_block(1000);
    return ttld.ndata->stats;
}

void tasvir_stats_reset() { ttld.ndata->stat_reset_req = 1; }

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
        "sync=%lu/s,%lu/s sync_t=%.1f%%,%luus/sync change=%luKB/s,%luKB/sync "
        "\n                                        "
        "rx=%luKB/s,%luKpps tx=%luKB/s,%luKpps "
        "(ipkts=%lu ibytes=%lu ierr=%lu imiss=%lu inombuf=%lu"
        ",opkts=%lu obytes=%lu oerr=%lu)",
        S * cur->success / interval_us, S * cur->failure / interval_us, 100. * cur->total_synctime_us / interval_us,
        cur->success > 0 ? cur->total_synctime_us / cur->success : 0, MS * cur->total_syncbytes / interval_us,
        cur->success > 0 ? cur->total_syncbytes / 1000 / cur->success : 0, MS * cur->total_bytes_rx / interval_us,
        MS * cur->total_pkts_rx / interval_us, MS * cur->total_bytes_tx / interval_us,
        MS * cur->total_pkts_tx / interval_us, s.ipackets, s.ibytes, s.ierrors, s.imissed, s.rx_nombuf, s.opackets,
        s.obytes, s.oerrors);

    avg->success += cur->success;
    avg->failure += cur->failure;
    avg->total_synctime_us += cur->total_synctime_us;
    avg->total_syncbytes += cur->total_syncbytes;
    avg->total_bytes_rx += cur->total_bytes_rx;
    avg->total_pkts_rx += cur->total_pkts_rx;
    avg->total_bytes_tx += cur->total_bytes_rx;
    avg->total_pkts_tx += cur->total_pkts_rx;

    cur->success = 0;
    cur->failure = 0;
    cur->total_synctime_us = 0;
    cur->total_syncbytes = 0;
    cur->total_bytes_rx = 0;
    cur->total_pkts_rx = 0;
    cur->total_bytes_tx = 0;
    cur->total_pkts_tx = 0;
    // tasvir_walk_areas(ttld.root_desc, &tasvir_print_area);
}
#endif
