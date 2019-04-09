#include "tasvir.h"

int tasvir_init_dpdk(uint16_t core) {
    int argc = 0, retval;
    char *argv[64];
    tasvir_str core_str;
    // tasvir_str mem_str;
    tasvir_str base_virtaddr;
    snprintf(core_str, sizeof(core_str), "%d", core);
    // snprintf(mem_str, sizeof(mem_str), "512,512");
    snprintf(base_virtaddr, sizeof(base_virtaddr), "%lx", TASVIR_ADDR_DPDK_BASE);
    argv[argc++] = "tasvir";
    argv[argc++] = "--base-virtaddr";
    argv[argc++] = base_virtaddr;
    argv[argc++] = "-l";
    argv[argc++] = core_str;
    argv[argc++] = "-n";
    argv[argc++] = "4";
    argv[argc++] = "--file-prefix";
    argv[argc++] = "tasvir";
    argv[argc++] = "--log-level";
    argv[argc++] = "7";
    // argv[argc++] = "--socket-mem";
    // argv[argc++] = mem_str;
    argv[argc++] = "--proc-type";
#ifdef TASVIR_DAEMON
    argv[argc++] = "primary";
#else
    argv[argc++] = "secondary";
#endif
    char* pciaddr = getenv("TASVIR_PCIADDR");
    if (pciaddr) {
        if (strncmp("net_bonding", pciaddr, 11) == 0) {
            argv[argc++] = "--vdev";
            argv[argc++] = pciaddr;
        } else {
            argv[argc++] = "--pci-whitelist";
            argv[argc++] = pciaddr;
        }
    }
    retval = rte_eal_init(argc, argv);
    if (retval < 0) {
        LOG_ERR("rte_eal_init failed");
        return -1;
    }
    return 0;
}

int tasvir_init_port() {
    const char* pciaddr = getenv("TASVIR_PCIADDR");
    if (!pciaddr)
        return 0;

    tasvir_str port_name;
    int nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0) {
        LOG_ERR("rte_eth_dev_count_avail() == 0");
        return -1;
    }

    strncpy(port_name, pciaddr, sizeof(port_name) - 1);
    if (strncmp("net_bonding", pciaddr, 11) == 0) {
        char *s = strchr(port_name, ',');
        if (s)
            *s = '\0';
    }

    if (rte_eth_dev_get_port_by_name(port_name, &ttld.ndata->port_id) != 0) {
        LOG_ERR("rte_eth_dev_get_port_by_name() failed, name=%s", port_name);
        return -1;
    }
    rte_eth_macaddr_get(ttld.ndata->port_id, &ttld.ndata->mac_addr);
    ether_addr_copy(&ttld.ndata->mac_addr, &ttld.ndata->nodecast_tid.nid.mac_addr);

    struct rte_eth_dev_info dev_info;
    struct rte_eth_conf port_conf;
    struct rte_eth_link link;
    uint64_t end_tsc;
    int retval;

    /* prepare configs */
    memset(&port_conf, 0, sizeof(port_conf));
    rte_eth_dev_info_get(ttld.ndata->port_id, &dev_info);
    port_conf.txmode.mq_mode = ETH_MQ_TX_NONE;
    port_conf.rxmode.mq_mode = ETH_MQ_RX_NONE;
    port_conf.rxmode.max_rx_pkt_len = ETHER_MAX_LEN;
    port_conf.rxmode.split_hdr_size = 0;
    // port_conf.rxmode.offloads = DEV_RX_OFFLOAD_CRC_STRIP;
    port_conf.intr_conf.lsc = 0;

    retval = rte_eth_dev_configure(ttld.ndata->port_id, 1, 1, &port_conf);
    if (retval < 0) {
        LOG_ERR("Cannot configure device: err=%d, port=%d", retval, ttld.ndata->port_id);
        return -1;
    }

    retval = rte_eth_rx_queue_setup(ttld.ndata->port_id, 0, TASVIR_RING_EXT_SIZE,
                                    rte_eth_dev_socket_id(ttld.ndata->port_id), NULL, ttld.ndata->mp);
    if (retval < 0) {
        LOG_ERR("rte_eth_rx_queue_setup:err=%d, port=%u", retval, (unsigned)ttld.ndata->port_id);
        return -1;
    }

    retval = rte_eth_tx_queue_setup(ttld.ndata->port_id, 0, TASVIR_RING_EXT_SIZE,
                                    rte_eth_dev_socket_id(ttld.ndata->port_id), NULL);
    if (retval < 0) {
        LOG_ERR("rte_eth_tx_queue_setup:err=%d, port=%u", retval, (unsigned)ttld.ndata->port_id);
        return -1;
    }

    retval = rte_eth_dev_start(ttld.ndata->port_id);
    if (retval < 0) {
        LOG_ERR("rte_eth_dev_start: err=%d, port=%u", retval, ttld.ndata->port_id);
        return -1;
    }

    retval = rte_eth_dev_set_link_up(ttld.ndata->port_id);
    if (retval < 0) {
        LOG_ERR("rte_eth_dev_set_link_up: err=%d, port=%u", retval, ttld.ndata->port_id);
        // return -1;
    }

    end_tsc = __rdtsc() + tasvir_usec2tsc(3 * S2US);
    do {
        rte_eth_link_get(ttld.ndata->port_id, &link);
    } while (__rdtsc() < end_tsc && link.link_status != ETH_LINK_UP);

    /*
    if (link.link_status != ETH_LINK_UP) {
        LOG_ERR("rte_eth_link_get_nowait: link is down port=%u", ttld.ndata->port_id);
        return -1;
    }
    */

    rte_eth_promiscuous_enable(ttld.ndata->port_id);
    rte_eth_stats_reset(ttld.ndata->port_id);
    rte_eth_xstats_reset(ttld.ndata->port_id);

    tasvir_str buf;
    ether_format_addr(buf, sizeof(buf), &ttld.ndata->mac_addr);
    LOG_INFO("port=%d mac=%s", ttld.ndata->port_id, buf);

    return 0;
}

