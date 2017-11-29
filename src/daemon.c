#include <assert.h>
#include <errno.h>
#include <execinfo.h>
#include <getopt.h>
#include <rte_cycles.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "tasvir.h"

#define BACKTRACE_BUFSIZE 32

void usage(char *exec) {
    fprintf(stderr, "Usage: %s -c core -p pciaddr [-r]\n", exec);
    exit(EXIT_FAILURE);
}

void handler(int sig) {
    void *buf[BACKTRACE_BUFSIZE];
    int nptrs = backtrace(buf, BACKTRACE_BUFSIZE);
    fprintf(stderr, "Error: received signal %d.\n", sig);
    backtrace_symbols_fd(buf, nptrs, STDERR_FILENO);
    exit(1);
}

int main(int argc, char **argv) {
    signal(SIGSEGV, handler);
    uint8_t daemon_type = TASVIR_THREAD_TYPE_DAEMON;
    int core = -1;
    char *pciaddr = NULL;

    int c;
    while (1) {
        int option_index = 0;
        static struct option long_options[] = {{"core", required_argument, 0, 'c'},
                                               {"pciaddr", required_argument, 0, 'p'},
                                               {"root", no_argument, 0, 'r'},
                                               {"help", no_argument, 0, 'h'},
                                               {0, 0, 0, 0}};

        c = getopt_long(argc, argv, "c:p:rh", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'c':
            core = atoi(optarg);
            break;
        case 'p':
            pciaddr = optarg;
            break;
        case 'r':
            daemon_type = TASVIR_THREAD_TYPE_ROOT;
            break;
        case 'h':
            usage(argv[0]);
            break;
        default:
            fprintf(stderr, "Unrecognized option 0%o\n", c);
            usage(argv[0]);
        }
    }

    if (optind < argc) {
        fprintf(stderr, "Extraneous arguments: ");
        while (optind < argc)
            fprintf(stderr, "%s ", argv[optind++]);
        fprintf(stderr, "\n");
        usage(argv[0]);
    }

    if (core == -1) {
        fprintf(stderr, "no core provided\n");
        usage(argv[0]);
    } else if (!pciaddr) {
        fprintf(stderr, "no pciaddr provided\n");
        usage(argv[0]);
    }

    tasvir_area_desc *root_desc = tasvir_init(daemon_type, core, pciaddr);
    if (!root_desc) {
        fprintf(stderr, "tasvir_daemon: tasvir_init_daemon failed\n");
        return -1;
    }

    while (true) {
        tasvir_service_block();
        rte_delay_us_block(5);
    }

    return 0;
}
