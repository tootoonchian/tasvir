set -e
RTE_SDK=$RTE_SDK ninja -C/srv/tasvir/build

set +e
for i in c{21..29}; do tmux kill-session -t tasvir_run_$i; done &>/dev/null
set -e

# export benchmark_area_len=$((4 * 1000 * 1000 * 1000))
export benchmark_area_len=$((1000))
export benchmark_stride=16
export benchmark_nr_writers=1
export benchmark_duration_ms=2000
export benchmark_service_us=1
export benchmark_sync_int=100
export benchmark_sync_ext=$((1000 * 1000 * 1000))

cnt=0
for nr_workers in 1 3 7 15 27 31 47 55; do
# for nr_workers in 1 3 7 15 31 55; do
    export host_list=c$((21 + cnt++)) nr_workers=$nr_workers
    /srv/tasvir/scripts/run.sh benchmark &
done
