#ifdef TASVIR_DAEMON
#include <assert.h>
#include <errno.h>
#include <execinfo.h>
#include <getopt.h>
#include <rte_cycles.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "tasvir.h"

#define BACKTRACE_BUFSIZE 32

/*
void usage(char *exec) {
    fprintf(stderr, "Usage: %s -c core -p pciaddr [-r]\n", exec);
    exit(EXIT_FAILURE);
}
*/

void handler(int sig) {
    void *buf[BACKTRACE_BUFSIZE];
    int nptrs = backtrace(buf, BACKTRACE_BUFSIZE);
    fprintf(stderr, "Error: received signal %d.\n", sig);
    backtrace_symbols_fd(buf, nptrs, STDERR_FILENO);
    exit(1);
}

int main() {
    signal(SIGSEGV, handler);
    /*
    int core = -1;
    char *pciaddr = NULL;

    while (1) {
        static struct option long_options[] = {{"core", required_argument, 0, 'c'},
                                               {"pciaddr", required_argument, 0, 'p'},
                                               {"root", no_argument, 0, 'r'},
                                               {"help", no_argument, 0, 'h'},
                                               {0, 0, 0, 0}};
        int c = getopt_long(argc, argv, "c:p:rh", long_options, NULL);
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
            ttld.is_root = true;
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
    if (setenv("TASVIR_PCIADDR", pciaddr, 1) != 0) {
        fprintf(stderr, "failed to environment variable TASVIR_PCIADDR to %s\n", pciaddr);
        return -1;
    }
    */

    if (!tasvir_init()) {
        fprintf(stderr, "tasvir_init_daemon failed\n");
        return -1;
    }

    while (true) {
        tasvir_service();
        rte_delay_us_block(1);
    }

    return 0;
}

#endif
