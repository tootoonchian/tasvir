#!/bin/bash
BENCH_SCRIPT=$(realpath ${BASH_SOURCE[0]})
SCRIPTDIR=$(dirname $BENCH_SCRIPT)
LOGDIR=$SCRIPTDIR/log
LOCKDIR=$LOGDIR/zz.lock
DONEDIR=$LOGDIR/zz.done
[ ! -d $LOCKDIR ] && mkdir -p $LOCKDIR
[ ! -d $DONEDIR ] && mkdir -p $DONEDIR

for i in $LOGDIR/*; do
    [ ! -f $i/t0.* ] && continue
    tail -n5 $i/t0.* | grep -q tasvir && rm -rf $i
done

rm -f $LOCKDIR/*
[ ! -f $LOCKDIR/lock ] && touch $LOCKDIR/lock

benchmark_stride=32
benchmark_duration_ms=2000
benchmark_service_us=25
benchmark_nr_writers=1
benchmark_sync_ext=$((60 * 1000 * 1000))

host_l=(c21 c22 c23 c24 c25 c26 c27 c28 c29)
size_l=(64 256 1024 2048 4096 8192 16384 32768 65536 131072 262144 524288 1048576)
sync_l=(1000 10000 100000)

reset; RTE_SDK=$RTE_SDK ninja -C/srv/tasvir/build

for host_list in ${host_l[@]}; do
    echo $host_list
    {
    cpu=$(ssh $host_list lscpu | grep -E '(family|Model):' | awk '{print $NF}' | xargs | awk '{print $1"-"$2}')
    ncores=$(ssh $host_list lscpu | grep node0 | sed -e s/,.*//g -e s/.*-//g)
    nr_workers_l=(1 3 5 7)
    # nr_workers_l=($(seq 1 2 $ncores))
    for nr_workers in ${nr_workers_l[*]}; do
        for size in ${size_l[*]}; do
            benchmark_area_len=$((size * 1024))
            for benchmark_sync_int in ${sync_l[*]}; do
                export benchmark_area_len benchmark_stride benchmark_duration_ms benchmark_service_us benchmark_nr_writers benchmark_sync_int benchmark_sync_ext nr_workers host_list
                runstr="$cpu.$nr_workers.$benchmark_nr_writers.$benchmark_duration_ms.$benchmark_service_us.$benchmark_area_len.$benchmark_stride.$benchmark_sync_int.$benchmark_sync_ext"
                [ -f $DONEDIR/$runstr -o -f $LOCKDIR/$runstr ] && continue
                ln $LOCKDIR/lock $LOCKDIR/$runstr 2>&- || continue
                echo ">> $host_list: $runstr"
                $SCRIPTDIR/run.sh benchmark &>/dev/null
                sleep 3
                while ssh $host_list "pgrep -f '^\S+tasvir_benchmark.*wid 0'"; do
                    sleep 0.5
                done &>/dev/null
                echo "<< $host_list: $runstr"
                touch $DONEDIR/$runstr
                rm $LOCKDIR/$runstr
            done
        done
    done
    } &
done
