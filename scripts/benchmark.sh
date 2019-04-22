#!/bin/bash
KB=1000
MB=1000000
GB=1000000000
MS2US=1000
S2US=1000000

BENCH_SCRIPT=$(realpath "${BASH_SOURCE[0]}")
SCRIPTDIR=$(dirname "$BENCH_SCRIPT")
LOGDIR=$SCRIPTDIR/log
LOCKDIR=$LOGDIR/zz.lock
DONEDIR=$LOGDIR/zz.done
PLOTDIR=$LOGDIR/zz.plots
COMPILER=${COMPILER:-gcc}

prepare() {
    for i in c{21..29}; do
        ssh $i pkill -f tasvir_ &
    done
    sleep 1
    [ ! -d "$LOCKDIR" ] && mkdir -p "$LOCKDIR"
    [ ! -d "$DONEDIR" ] && mkdir -p "$DONEDIR"
    rm -f "$LOCKDIR"/*

    rm -f /tmp/die.tasvir_benchmark

    for i in c{21..29}; do
        tmux kill-session -t tasvir_run_$i
    done &>/dev/null

    # delete incomplete results
    for i in "$LOGDIR"/*; do
        [[ "$i" == */zz.* ]] && continue
        if ! stat -t "$i"/t0.* &>/dev/null || tail -n5 "$i"/t0.* | grep -q tasvir; then
            rm -rf "$i"
        fi
    done

    touch "$LOCKDIR/lock"
    if [[ "$COMPILER" == both ]]; then
        for COMPILER in gcc clang; do
            "$SCRIPTDIR/run.sh" compile || exit 1
        done
        COMPILER=both
    else
        "$SCRIPTDIR/run.sh" compile || exit 1
    fi
}

benchmark_run_once() {
    export COMPILER benchmark_area_len benchmark_nr_rounds benchmark_stride benchmark_duration_ms benchmark_service_us benchmark_nr_writers benchmark_sync_int benchmark_sync_ext nr_workers host_list
    runstr="compiler=$COMPILER,cpu=$cpu,nr_workers=$nr_workers,benchmark_nr_writers=$benchmark_nr_writers,benchmark_duration_ms=$benchmark_duration_ms,benchmark_service_us=$benchmark_service_us,benchmark_area_len=$benchmark_area_len,benchmark_stride=$benchmark_stride,benchmark_sync_int=$benchmark_sync_int,benchmark_sync_ext=$benchmark_sync_ext"
    if [[ "$BENCH_TEST" != 1 ]]; then
        [ -f "$DONEDIR/$runstr" ] || [ -f "$LOCKDIR/$runstr" ] && return
        ln "$LOCKDIR/lock" "$LOCKDIR/$runstr" 2>&- || return
    fi
    echo ">> $host_list: $runstr"
    "$SCRIPTDIR/run.sh" benchmark &>/dev/null
    sleep 3
    while ssh "$host_list" "pgrep -f '^\\S+tasvir_benchmark.*wid 0'"; do
        sleep 0.5
    done &>/dev/null
    echo "<< $host_list: $runstr"
    if [[ "$BENCH_TEST" != 1 ]]; then
        touch "$DONEDIR/$runstr"
        rm "$LOCKDIR/$runstr"
    fi
}

run_all() {
    benchmark_duration_ms=${benchmark_duration_ms:-2000}
    benchmark_nr_rounds=${benchmark_nr_rounds:-3}
    declare -ga benchmark_area_len_l=${benchmark_area_len_l:-($KB $((100*KB)) $MB $((10*MB)) $((100*MB)) $GB)}
    declare -ga benchmark_nr_writers_l=${benchmark_nr_writers_l:-(1)}
    declare -ga benchmark_service_us_l=${benchmark_service_us_l:-(10)}
    declare -ga benchmark_stride_l=${benchmark_stride_l:-(64)}
    declare -ga benchmark_sync_int_l=${benchmark_sync_int_l:-($MS2US $((10*MS2US)) $((100*MS2US)))}
    declare -ga benchmark_sync_ext_l=${benchmark_sync_ext_l:-($((1000*S2US)))}

    declare -ga compiler_l=${compiler_l:-(gcc clang)}
    declare -ga host_l=${host_l:-(c21 c22 c23 c24 c25 c26 c27 c28 c29)}
    cpu=$(ssh "${host_l[0]}" lscpu | grep -E '(family|Model):' | awk '{print $NF}' | xargs | awk '{print $1"-"$2}')
    # ncores=$(ssh ${host_l[0]} lscpu | grep node0 | sed -e s/,.*//g -e s/.*-//g)
    # nr_workers_l=($(seq 1 2 $ncores))
    declare -ga nr_workers_l=${nr_workers_l:-(1 7 15 23 31 39 47)}
    local i=0

    for host_list in "${host_l[@]}"; do
        if ! ping -q -c1 -w1 -W1 "$host_list" &>/dev/null; then
            echo "$host_list is not responding"
            continue
        fi
        {
        for COMPILER in ${compiler_l[*]}; do
            for nr_workers in ${nr_workers_l[*]}; do
                for benchmark_nr_writers in ${benchmark_nr_writers_l[*]}; do
                    [ "$benchmark_nr_writers" -gt "$nr_workers" ] && continue
                    for benchmark_area_len in ${benchmark_area_len_l[*]}; do
                        for benchmark_service_us in ${benchmark_service_us_l[*]}; do
                            for benchmark_stride in ${benchmark_stride_l[*]}; do
                                for benchmark_sync_int in ${benchmark_sync_int_l[*]}; do
                                    for benchmark_sync_ext in ${benchmark_sync_ext_l[*]}; do
                                        benchmark_run_once
                                        [ -f /tmp/die.tasvir_benchmark ] && exit
                                    done
                                done
                            done
                        done
                    done
                done
            done
        done
        } &
    done
}

run_test() {
    BENCH_TEST=1
    benchmark_duration_ms=${benchmark_duration_ms:-1000}
    benchmark_nr_rounds=${benchmark_nr_rounds:-3}
    declare -ga benchmark_area_len_l=${benchmark_area_len_l:-($((100 * MB)))}
    declare -ga benchmark_service_us_l=${benchmark_service_us_l:-(5)}
    declare -ga benchmark_sync_int_l=${benchmark_sync_int_l:-(10000)}
    declare -ga nr_workers_l=${nr_workers_l:-(13)}
    declare -a host_l_copy=${host_l:-(c22 c23)} # c25 c26 c27 c28 c29
    declare -a compiler_l=${compiler_l:-(gcc clang)}

    local i=0
    for h in ${host_l_copy[*]}; do
        i=$((i + 1))
        if [[ "$COMPILER" == both ]]; then
            if [[ $((i % 2)) -eq 0 ]]; then
                compiler_l=(gcc)
            else
                compiler_l=(clang)
            fi
        else
            compiler_l=$COMPILER
        fi
        host_l=("$h")
        run_all
    done
}

run_test2() {
    benchmark_duration_ms=${benchmark_duration_ms:-1000}
    benchmark_nr_rounds=${benchmark_nr_rounds:-2}
    declare -ga benchmark_area_len_l=${benchmark_area_len_l:-($((32 * MB)))}
    declare -ga benchmark_service_us_l=${benchmark_service_us_l:-(2)}
    declare -ga benchmark_sync_int_l=${benchmark_sync_int_l:-(100)}
    declare -ga nr_workers_l=${nr_workers_l:-(1 3 7 15 23)}
    declare -a compiler_l=${compiler_l:-(gcc)}

    run_all
}

plot_and_sigal() {
    rm -rf "$PLOTDIR"
    local SIGALCONF=/tmp/sigal.conf.py
    cat >"$SIGALCONF" <<EOF
source = 'pictures'
theme = 'colorbox'
use_orig = True
img_size = (1600, 1200)
thumb_size = (333, 250)
ignore_directories = []
ignore_files = []
EOF
    "$SCRIPTDIR/benchmark_plot.py" "$LOGDIR"
    rm -rf _build && sigal build -c "$SIGALCONF" "$LOGDIR" && sigal serve -c "$SIGALCONF"
}

prepare || exit

if [ "$1" = test ]; then
    run_test
elif [ "$1" = test2 ]; then
    run_test2
elif [ "$1" = all ]; then
    run_all
elif [ "$1" = plot_and_sigal ]; then
    plot_and_sigal
else
    echo "usage: $0 test|all|plot_and_sigal"
fi
