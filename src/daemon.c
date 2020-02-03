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

void handler(int sig) {
    void *buf[BACKTRACE_BUFSIZE];
    int nptrs = backtrace(buf, BACKTRACE_BUFSIZE);
    fprintf(stderr, "Error: received signal %d.\n", sig);
    backtrace_symbols_fd(buf, nptrs, STDERR_FILENO);
    exit(1);
}

int main() {
    signal(SIGSEGV, handler);

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
