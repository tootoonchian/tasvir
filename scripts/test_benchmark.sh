set -e
RTE_SDK=$RTE_SDK ninja -C/srv/tasvir/build

set +e
for i in c{21..29}; do tmux kill-session -t tasvir_run_$i; done &>/dev/null
set -e

export benchmark_area_len=$((100 * 1024 * 1024)) benchmark_stride=16 benchmark_nr_writers=1 benchmark_duration_ms=5000 benchmark_service_us=1 benchmark_sync_int=100 benchmark_sync_ext=100000

cnt=0
for nr_workers in 3 7 15 27 31 47 55; do
    export host_list=c$((21 + cnt++)) nr_workers=$nr_workers
    /srv/tasvir/scripts/run.sh benchmark &
done
