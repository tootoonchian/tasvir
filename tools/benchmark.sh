#!/bin/bash

# TODO: read host lists and core counts from conf file

BENCH_SCRIPT=$(realpath "${BASH_SOURCE[0]}")
SCRIPTDIR=$(dirname "$BENCH_SCRIPT")
LOGDIR=$SCRIPTDIR/log
LOCKDIR=$LOGDIR/zz.lock
DONEDIR=$LOGDIR/zz.done
PLOTDIR=$LOGDIR/zz.plots
COMPILER=${COMPILER:-gcc}

KB=1000
MB=1000000
GB=1000000000
MS2US=1000
S2US=1000000

_init() {
    for i in c{21..28}; do
        ssh -f $i pkill tasvir_ &
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
    COMPILER=gcc "$SCRIPTDIR/run.sh" compile || exit 1
    COMPILER=clang "$SCRIPTDIR/run.sh" compile || exit 1

    # populate default values
    declare -gA cpu_model
    declare -gA compiler_v

    declare -g benchmark_duration_ms=${benchmark_duration_ms:-1000}
    declare -g benchmark_nr_rounds=${benchmark_nr_rounds:-3}
    declare -ga benchmark_area_len_l=${benchmark_area_len_l:-($((10 * MB)))}
    declare -ga benchmark_nr_writers_l=${benchmark_nr_writers_l:-(1)}
    declare -ga benchmark_stride_l=${benchmark_stride_l:-(64)}

    declare -ga benchmark_service_us_l=${benchmark_service_us_l:-(5)}
    declare -ga benchmark_sync_int_l=${benchmark_sync_int_l:-($MS2US)}
    declare -ga benchmark_sync_ext_l=${benchmark_sync_ext_l:-($((1000 * S2US)))}

    declare -ga compiler_l=${compiler_l:-(gcc)}
    declare -ga host_l=${host_l:-(c21 c22 c23 c24 c25 c26 c27 c28)}
    declare -ga nr_workers_l=${nr_workers_l:-(1)}
}

_run_one() {
    local h=$host_list
    local hc=${host_list}_${COMPILER}
    [ -z "${cpu_model[$h]}" ] && cpu_model[$h]=$(ssh "${host_l[0]}" lscpu | grep -E '(family|Model):' | awk '{print $NF}' | xargs | awk '{print $1"-"$2}')
    [ -z "${compiler_v[$hc]}" ] && compiler_v[$hc]=$COMPILER-v$(ssh "${host_l[0]}" $COMPILER --version | head -n1 | awk '{print $3}' | tr -d ')')

    export COMPILER benchmark_area_len benchmark_nr_rounds benchmark_stride benchmark_duration_ms benchmark_service_us benchmark_nr_writers benchmark_sync_int benchmark_sync_ext nr_workers host_list
    printf -v runstr "nr_workers=%02d,nr_writers=%02d,area_len_kb=%07d,stride=%04d,duration_ms=%05d,service_us=%02d,sync_int=%06d,sync_ext=%06d,cpu=%s,compiler=%s" \
            $nr_workers $benchmark_nr_writers $((benchmark_area_len/1000)) $benchmark_stride $benchmark_duration_ms $benchmark_service_us $benchmark_sync_int $benchmark_sync_ext \
            ${cpu_model[$h]} ${compiler_v[$hc]}
    if [[ "$BENCH_TEST" != 1 ]]; then
        [ -d "$DONEDIR/$runstr" ] || [ -f "$LOCKDIR/$runstr" ] && return
        ln "$LOCKDIR/lock" "$LOCKDIR/$runstr" 2>&- || return
    fi
    echo ">> $host_list: $runstr"
    logdir=$("$SCRIPTDIR/run.sh" benchmark | grep logdir= | sed s/logdir=//g)
    logfile=$logdir/t0.$host_list
    sleep 3
    while ssh "$host_list" "pgrep -f '^\\S+tasvir_benchmark.*wid 0'"; do
        sleep 0.5
    done &>/dev/null
    ssh "$host_list" sync
    if [[ "$BENCH_TEST" != 1 ]]; then
        if [ -f $logfile ] && grep -Eq '(COMMAND_EXIT_CODE="0"|exited normally)' $logfile; then
            echo "<< $host_list: $runstr"
            mv $logdir "$DONEDIR/$runstr"
        else
            echo "FAILED $host_list: $runstr"
        fi
        rm "$LOCKDIR/$runstr"
    fi
}

_run_loop() {
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
                                        _run_one
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

disassemble() {
    declare -A map
    map[false]=0
    map[true]=1
    for COMPILER in clang gcc; do
        COMPILER=$COMPILER ./run.sh compile
        # objdump -glCDS ../build.$COMPILER/bin/tasvir_benchmark > /tmp/objdump.$COMPILER
        for wt in 0; do
            for dt in 0; do
                for do_log in false true; do
                    for do_service in false true; do
                        fname=/tmp/gdbdasm.$COMPILER.wt${wt}_dt${dt}_l${map[$do_log]}_s${map[$do_service]}
                        gdb -batch -ex "disassemble/s experiment<(WorkloadType)$wt, (DistType)$dt, $do_service, $do_log, true, 64>" ../build.$COMPILER/bin/tasvir_benchmark > $fname
                    done
                done
            done
        done
    done
}

monitor() {
    PCM_PATH=/srv/tools/intel/pcm
    CMTCAT_PATH=/srv/tools/intel/intel-cmt-cat
    PATH=$PATH:$PCM_PATH:$CMTCAT_PATH
    modprobe msr
    cores=54-55 #28-55
    events=l2_rqsts.all_pf,l2_rqsts.miss,l2_lines_out.useless_hwpf
    events+=,LLC-loads,LLC-loads-misses
    events+=,LLC-stores,LLC-store-misses
    events+=,llc_misses.mem_read,llc_misses.mem_write
    #events+=,mem_inst_retired.split_stores,mem_load_l3_miss_retired.local_dram,mem_load_l3_miss_retired.remote_dram
    #events+=,llc_references.streaming_full,llc_references.streaming_partial
    #events+=,dTLB-load-misses,dTLB-store-misses
    #events+=,dtlb_store_misses.miss_causes_a_walk,dtlb_store_misses.stlb_hit,dtlb_store_misses.walk_active,dtlb_store_misses.walk_completed,dtlb_store_misses.walk_completed_1g,dtlb_store_misses.walk_completed_2m_4m,dtlb_store_misses.walk_completed_4k,dtlb_store_misses.walk_pending
    #cmd="perf stat -C $cores -e $events -I 1000"
    #cmd="turbostat -c $cores -i 0.5"
    #cmd="pcm-memory.x 1"
    #cmd="pcm-numa.x 1"
    cmd="LD_LIBRARY_PATH=$CMTCAT_PATH/lib $CMTCAT_PATH/pqos/pqos -r -m all:$cores"
    for i in c{22..26}; do
        tmux split-window ssh $i "$cmd"\; select-layout even-vertical
    done
    tmux select-layout tile
    eval $cmd
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

test1() {
    BENCH_TEST=1
    declare -ga host_l_copy=(c22 c23)

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
        _run_loop
    done
}

test_cachesize() {
    declare -ga compiler_l=(gcc clang)
    declare -ga benchmark_area_len_l=($((30*KB)) $((MB)) $((38*MB))) # L1d: 32k, L2: 1MB, L3: 38.5MB
    declare -ga benchmark_sync_int_l=($MS2US)

    _run_loop
}

test_meh() {
    declare -ga compiler_l=(gcc clang)
    declare -ga nr_workers_l=(1 3 7 15 23)
    declare -ga benchmark_area_len_l=($KB $((10*KB)) $((100*KB)) $MB $((10*MB)) $((100*MB)) $GB)
    declare -ga benchmark_sync_int_l=(10 100 $((MS2US)) $((10*MS2US)) $((100*MS2US)))

    _run_loop
}

test_sync_scale() {
    declare -ga benchmark_area_len_l=($((1*GB)))
    declare -ga benchmark_sync_int_l=(10000)

    _run_loop
}

test_sync_int_scale() {
    declare -ga compiler_l=(gcc)
    declare -ga benchmark_area_len_l=($KB $((10*KB)) $((100*KB)) $MB $((10*MB)) $((100*MB)) $GB)
    declare -ga benchmark_sync_int_l=(10 100 $((MS2US)) $((10*MS2US)) $((100*MS2US)))
    declare -ga nr_workers_l=(1 3 7 11 15 19 23 27)

    _run_loop
}

test_latency() {
    export host_list="c21 c22 c23 c24 c25 c26 c27 c28"
    nr_workers=1 counter_sync_int_us=1 counter_sync_ext_us=1 counter_count_to=100 "$SCRIPTDIR/run.sh" counter
    for nr_nodes in {1..8}; do
        for nr_workers in {1..27..2}; do
            [[ $nr_workers -ne 1 ]] && continue
            printf -v host_nr_workers "$((nr_workers + 1)) %.0s" $(seq 1 $nr_nodes)
            nr_workers=$((nr_nodes * nr_workers))
            export host_nr_workers nr_workers
            printf -v runstr "counter,nr_nodes=%02d,nr_workers=%03d" $nr_nodes $nr_workers
            [ -d "$DONEDIR/$runstr" ] && continue
            echo nr_nodes=$nr_nodes,nr_workers=$nr_workers, $runstr ... $host_nr_workers
            logdir=$(counter_sync_int_us=1 counter_sync_ext_us=1 counter_count_to=10000 "$SCRIPTDIR/run.sh" counter | grep logdir= | sed s/logdir=//g)
            logfile=$logdir/t0.c21
             while pgrep -f '^\S+tasvir_counter 0'; do
                sleep 0.5
            done &>/dev/null
            sync
            if [ -f $logfile ] && grep -Eq '(COMMAND_EXIT_CODE="0"|exited normally)' $logfile; then
                echo success
                mv $logdir "$DONEDIR/$runstr"
            fi
        done
    done
}

if [ ! -z "$1" ]; then
    if echo "$1" | grep -q test; then
        _init || exit 1
    fi
    $1
fi
