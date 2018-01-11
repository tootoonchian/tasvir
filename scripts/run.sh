#!/bin/bash
TASVIR_SRCDIR=/opt/tasvir
TASVIR_BINDIR=$TASVIR_SRCDIR/build/bin
RUNSCRIPT=$(realpath $0)
PIDFILE_PREFIX=/var/run/tasvir-

prepare() {
    sysctl vm.nr_hugepages=1050

    max_freq=$(cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq)
    for i in /sys/devices/system/cpu/*/cpufreq; do
        echo performance > $i/scaling_governor
        echo $max_freq > $i/scaling_min_freq
        echo $max_freq > $i/scaling_max_freq
    done

    export CC=$(which clang)
    export CXX=$(which clang++)

    mkdir $TASVIR_SRCDIR/build &>/dev/null
    cd $TASVIR_SRCDIR/build
    cmake -DCMAKE_BUILD_TYPE=Release .. || exit
    make || exit
}

cleanup() {
    for pidfile in ${PIDFILE_PREFIX}*; do
        start-stop-daemon --stop --retry 3 --remove-pidfile --pidfile $pidfile &>/dev/null
    done
    rm -f /dev/shm/tasvir /dev/hugepages/tasvir* /var/run/.tasvir_config &>/dev/null
}


generate_cmd() {
    generate_cmd_thread() {
        local bgflag
        local pmucmd
        local gdbcmd
        local pmucmd="/opt/tools/pmu-tools/toplev.py -l4 -S"
        local stdbufcmd="stdbuf -o 0 -e 0"
        local redirect
        if [ $tid == d -o $tid == 0 ]; then
            #gdbcmd="gdb -ex run --args"
            redirect="2>&1 | tee $logfile"
        else
            bgflag="--background"
            redirect=">$logfile 2>&1"
        fi
        #bgflag=""
        #gdbcmd="gdb -ex run --args"
        #redirect="2>&1 | tee $logfile"

        cmd_thread="start-stop-daemon $bgflag --start --make-pidfile --pidfile ${PIDFILE_PREFIX}%TID%.pid --startas /bin/bash -- -c
                    \"exec /usr/bin/numactl -C %CORE% $gdbcmd $stdbufcmd $* $redirect\""
        cmd_thread=$(echo $cmd_thread | sed -e s/%CORE%/$core/g -e s/%TID%/$tid/g -e s/%NTHREADS%/$nthreads/g)
        ((core++))
    }

    local core=${core:-0}
    local pciaddr=${pciaddr:-85:00.0}
    local nthreads=${nthreads:-1}
    local delay=${delay:-2}

    local cmd
    local cmd_app="$*"
    local cmd_daemon="$TASVIR_BINDIR/tasvir_daemon --core %CORE% --pciaddr $pciaddr --root"
    local cmd_thread
    local session=tasvir_run
    local tid=d
    local w=0
    local timestamp=`date +"%Y%m%d-%H%M%S"`
    local window=n$nthreads-$timestamp
    local logfile="$(dirname $RUNSCRIPT)/log/$timestamp.n$nthreads.t%TID%"

    cmd="byobu "
    cmd+="set-option -gq mouse-utf8 on\; "
    cmd+="set-option -gq mouse-resize-pane on\; "
    cmd+="set-option -gq mouse-select-pane on\; "
    cmd+="set-option -gq mouse-select-window on\; "
    cmd+="set-window-option -gq mode-mouse on\; "
    cmd+="set-window-option -gq remain-on-exit off\; "
    tmux has-session -t $session &>/dev/null || cmd+="new-session -Ads $session\; "
    [ -z $TMUX ] && cmd+="attach-session -t $session\; " || cmd+="switch-client -t $session\; "

    # run the daemon
    generate_cmd_thread $cmd_daemon
    cmd+="new-window -t $session -n $window-$w '. $RUNSCRIPT; $cmd_thread; cleanup;'\; "

    for tid in `seq 0 $((nthreads - 1))`; do
        [ $tid -ne 0 -a $((tid % 16)) -eq 0 ] && cmd+="; byobu "
        [ $tid -ne 0 -a $((tid % 4)) -eq 0 ] && cmd+="new-window -t $session -n $window-$((++w)) " || cmd+="split-window -t $session:$window-$w "
        generate_cmd_thread $cmd_app
        # run the worker
        local cmd_last
        [ $tid -eq 0 ] && cmd_last='bash' || cmd_last=''
        cmd+="'ulimit -c unlimited; sleep $delay; $cmd_thread; $cmd_last'\; "
    done

    cmd+="select-layout -t $session:$window-0 main-horizontal\; "
    for wid in `seq 1 $w`; do
        cmd+="select-layout -t $session:$window-$wid tiled \; "
    done

    echo "$cmd"
}

benchmark() {
    nr_writes=$((200 * 1000 * 1000))
    writes_per_service=100
    area_len=$((100 * 1024 * 1024))
    stride=8

    cleanup
    eval $(generate_cmd $TASVIR_BINDIR/tasvir_benchmark %CORE% $nr_writes $writes_per_service $area_len $stride)
}

ycsb() {
    ycsb_dir=/opt/tasvir/misc/YCSB-C

    cleanup
    eval $(generate_cmd $TASVIR_BINDIR/kvstore -s %TID% -n 2 -c %CORE% -a $ycsb_dir/wtest-2.access -l $ycsb_dir/wtest-2.load)
}

cyclades() {
    model=${model:-matrix_completion}
    #model=${model:-least_squares}
    #model=${model:-word_embeddings}
    #model=${model:-matrix_inverse}
    updater=${updater:-sparse_sgd}
    #updater=${updater:-saga}
    trainer=${trainer:-cyclades_trainer}
    nepochs=${nepoch:-11}
    batch=${batch:-2000}
    #batch=${batch:-4250}
    #batch=${batch:-1000}
    dataset=${dataset:-/opt/tasvir/apps/cyclades/data/movielens/ml-1m/movielens_1m.data}
    #dataset=${dataset:-/opt/tasvir/apps/cyclades/data/word_embeddings/w2v_graph}
    #dataset=${dataset:-/opt/tasvir/apps/cyclades/data/nh2010/nh2010/nh2010.data}
    learning_rate=${learning_rate:-2e-2}
    #learning_rate=${learning_rate:-1e-10}
    #learning_rate=${learning_rate:-3e-14}

    [ ! -z "$model" ] && model=--$model
    [ ! -z "$updater" ] && updater=--$updater
    [ ! -z "$trainer" ] && trainer=--$trainer

    cleanup
    eval $(generate_cmd $TASVIR_BINDIR/tasvir_cyclades --wid %TID% --core %CORE% --print_loss_per_epoch --print_partition_time --n_threads=%NTHREADS% --learning_rate=$learning_rate $model $updater $trainer --cyclades_batch_size=$batch --n_epochs=$nepochs --data_file=$dataset)
}

setup_env() {
    # Timezone
    ln -fs /usr/share/zoneinfo/America/Los_Angeles /etc/localtime
    dpkg-reconfigure -f noninteractive tzdata

    # Upgrade
    # sed -i -e s/jessie/testing/g -e s/stretch/testing/g /etc/apt/sources.list
    apt-get update
    apt-get -y dist-upgrade

    # Packages
    apt-get install -y \
        aptitude build-essential byobu clang clang-format clang-tidy cmake curl gdb git llvm-dev python3 python3-pip uthash-dev uuid-dev vim-nox
    byobu-enable-prompt

    # DPDK
    cat >/etc/sysctl.d/50-dpdk.conf <<EOF
    vm.nr_hugepages = 200
EOF
    service procps restart
    cat >/etc/profile.d/dpdk.sh <<EOF
export RTE_SDK=/opt/dpdk
export RTE_TARGET=tasvir
EOF
    chmod +x /etc/profile.d/dpdk.sh

    # Vim
    cat >/root/.vimrc.before.local <<EOF
let g:spf13_bundle_groups=['general', 'writing', 'programming', 'python', 'misc', 'youcompleteme']
let g:ycm_global_ycm_extra_conf = '~/.vim/.ycm_extra_conf.py'
EOF
    cat >/root/.vimrc.bundles.local <<EOF
Bundle 'rhysd/vim-clang-format'
EOF
    sh <(curl https://j.mp/spf13-vim3 -L)
    vim +BundleInstall! +BundleClean +q
    #cp /opt/.ycm_extra_conf.py /root/.vim/
    cd ~/.vim/bundle/YouCompleteMe
    YCM_CORES=1 python3 ./install.py --clang-completer --system-libclang
}

[ $# == 1 ] && $1
