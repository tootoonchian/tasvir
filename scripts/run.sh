#!/bin/bash
TASVIR_SRCDIR=/opt/tasvir
TASVIR_BINDIR=$TASVIR_SRCDIR/build/bin
THIS=$TASVIR_SRCDIR/scripts/run.sh
PID_DAEMON=/var/run/tasvir-daemon.pid
PID_BENCH=/var/run/tasvir-bench.pid

prepare() {
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
    start-stop-daemon -q --stop --remove-pidfile --pidfile $PID_BENCH &>/dev/null
    start-stop-daemon -q --stop --remove-pidfile --pidfile $PID_DAEMON &>/dev/null
    rm -f /dev/shm/tasvir /dev/hugepages/tasvir* &>/dev/null
}

benchmark() {
    nr_writes=$((500 * 1000 * 1000))
    writes_per_service=100
    area_len=$((10 * 1024 * 1024))
    stride=8
    core_daemon=0
    core_bench=1
    session=tasvir_benchmark
    window_name=`date +"%Y%m%d-%H%M%S"`
    attach_cmd=$(if [ -z $TMUX ]; then echo "attach-session"; else echo "switch-client"; fi)
    #wrapper="/opt/tools/pmu-tools/toplev.py -l4 -S"
    wrapper="gdb -ex run --args"
    #wrapper=""

    cleanup
    prepare

    byobu new-session -AdPs $session &>/dev/null
    byobu $attach_cmd -t $session \; \
        new-window -t $session -n $window_name "start-stop-daemon --start --make-pidfile --pidfile $PID_DAEMON --exec /usr/bin/numactl -- -C $core_daemon $wrapper $TASVIR_BINDIR/tasvir_daemon root $core_daemon; $THIS cleanup; bash; byobu kill-window" \; \
        split-window -t $session:$window_name -h "sleep 0.2; start-stop-daemon --start --make-pidfile --pidfile $PID_BENCH --exec /usr/bin/numactl -- -C $core_bench $wrapper $TASVIR_BINDIR/tasvir_benchmark $core_bench $nr_writes $writes_per_service $area_len $stride; $THIS cleanup; bash; byobu kill-window"
}

dev() {
    session=tasvir_dev
    attach_cmd=$(if [ -z $TMUX ]; then echo "attach-session"; else echo "switch-client"; fi)
    byobu new-session -AdPs $session &>/dev/null
    byobu $attach_cmd -t $session \; \
        new-window -t $session -n dev "vim -O $TASVIR_SRCDIR/{include/tasvir.h,src/tasvir.c}"
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
    vm.nr_hugepages = 50
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
