#!/bin/bash
BENCH_SCRIPT=$(realpath ${BASH_SOURCE[0]})
SCRIPTDIR=$(dirname $BENCH_SCRIPT)
LOGDIR=$(dirname $BENCH_SCRIPT/log)

result=log/bench.csv
echo sync_int,size,service,sync,log,direct,indirect,full, > $result

nthreads=1
nr_writes=$((50 * 1000 * 1000))
writes_per_service=200
stride=16
sync_ext=$((60 * 1000 * 1000))
for size in 512 1024 16384 262144; do
    area_len=$((size * 1024))
    for sync_int in 1000 10000 100000; do
        log_dir=$LOGDIR/n$nthreads.sync$sync_int-$sync_ext.size$size
        [ -d $log_dir ] && continue
        export nr_writes writes_per_service stride sync_int sync_ext area_len nthreads
        ./run.sh benchmark
        sleep 0.5
        while pgrep tasvir_daemon &>/dev/null; do
            sleep 0.5
        done
        vals=$(grep overhead log/* | awk '{print $NF}' | sed s/%//g | tr '\n' ',')
        echo $sync_int,$size,$vals >> $result

        mkdir $log_dir
        mv log/2018* $log_dir/
    done
done
