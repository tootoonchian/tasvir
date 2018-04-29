#!/bin/bash

RUNSCRIPT=$(realpath ${BASH_SOURCE[0]})
SCRIPTDIR=$(dirname $RUNSCRIPT)
LOGDIR=$SCRIPTDIR/log
TASVIR_SRCDIR=$(realpath `dirname $RUNSCRIPT`/..)
TASVIR_CONFDIR=$TASVIR_SRCDIR/etc
TASVIR_CONF=$TASVIR_CONFDIR/tasvir.conf
TASVIR_BINDIR=$TASVIR_SRCDIR/build/bin
PIDFILE_PREFIX=/var/run/tasvir-

prepare() {
    echo never >/sys/kernel/mm/transparent_hugepage/enabled
    sysctl vm.nr_hugepages=1050 &>/dev/null

    modprobe igb_uio &>/dev/null
    if [[ ${HOST_NIC[$HOSTNAME]} = *"bonding="*  ]]; then
        echo ${HOST_NIC[$HOSTNAME]} | sed 's/slave=/\n/g' | sed 's/,.*//g' | grep ^0000: | while read i; do
            $RTE_SDK/usertools/dpdk-devbind.py --force -b igb_uio $i &>/dev/null
        done
    else
        $RTE_SDK/usertools/dpdk-devbind.py --force -b igb_uio ${HOST_NIC[$HOSTNAME]} &>/dev/null
    fi

    for pidfile in ${PIDFILE_PREFIX}*; do
        start-stop-daemon --stop --retry 3 --remove-pidfile --pidfile $pidfile &>/dev/null
    done
    rm -f /dev/shm/tasvir /dev/hugepages/tasvir* /var/run/.tasvir_config &>/dev/null

    echo 1 > /sys/module/processor/parameters/ignore_ppc
    echo 0 > /proc/sys/kernel/nmi_watchdog
    [ -f /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq ] && max_freq=$(cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq)
    for cpu in /sys/devices/system/cpu/cpu[0-9]*; do
        # fix core frequency
        if [ -d $cpu/cpufreq ]; then
            echo performance > $cpu/cpufreq/scaling_governor
            echo $max_freq > $cpu/cpufreq/scaling_min_freq
            echo $max_freq > $cpu/cpufreq/scaling_max_freq
        fi
        # disable c states
        if [ -d $cpu/cpuidle ]; then
            for state in $cpu/cpuidle/state[1-9]/disable; do
                echo 1 > $state/disable
            done
        fi
        # disable p states
        if [ -d /sys/devices/system/cpu/intel_pstate ]; then
            echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo
            echo 100 > /sys/devices/system/cpu/intel_pstate/min_perf_pct
            echo 100 > /sys/devices/system/cpu/intel_pstate/max_perf_pct
        fi
    done &>/dev/null
    # disable uncore frequency scaling
    wrmsr -a 0x620 0x1d1d
    date > /tmp/prepare.done
    pkill -f "tail -f.*log"
    mkdir $LOGDIR &>/dev/null
}

compile() {
    #export CC=$(which clang)
    #export CXX=$(which clang++)

    mkdir $TASVIR_SRCDIR/build &>/dev/null
    cd $TASVIR_SRCDIR/build
    cmake -DCMAKE_BUILD_TYPE=Release .. || exit
    make || exit
}

generate_cmd() {
    generate_cmd_thread() {
        local gdbcmd
        local redirect
        if [ $tid == d -o $tid == 0 ]; then
            #gdbcmd="gdb -ex run --args"
            redirect="2>&1 | tee $logfile"
        else
            redirect=">$logfile 2>&1"
        fi
        #gdbcmd="gdb -ex run --args"
        #redirect="2>&1 | tee $logfile"
        redirect=">$logfile 2>&1"

        cmd_thread="start-stop-daemon --background --start --make-pidfile --pidfile ${PIDFILE_PREFIX}%TID%.pid --startas /bin/bash -- -c
                    \"exec /usr/bin/numactl -C %CORE% $gdbcmd stdbuf -o 0 -e 0 $* $redirect\";"
        cmd_thread+="sleep 1; stdbuf -o 0 -e 0 tail -n 1000 -f $logfile"
        cmd_thread=$(echo $cmd_thread | sed -e s/%CORE%/$core/g -e s/%TID%/$tid/g -e s/%NTHREADS%/$nthreads/g -e s/%HOST%/$host/g)
        ((core--))
    }

    local nthreads=${nthreads:-1}
    local delay=${delay:-3}

    local host_counter=0
    local host_list=("${host_list[@]:-${!HOST_NCORES[@]}}")
    local host=${host_list[0]}

    local cmd
    local cmd_app="$*"
    local cmd_ssh
    local cmd_thread
    local session=tasvir_run
    local w=-1
    local p=0
    local timestamp=`date +"%Y%m%d-%H%M%S"`
    local window
    local logdir="$LOGDIR/$timestamp"
    local manifest="$logdir/manifest"
    local logfile="$logdir/t%TID%.%HOST%"
    local threads_this=0

    local cmd_byobu="byobu "
    cmd_byobu+="set-option -gq mouse-utf8 on\; "
    cmd_byobu+="set-option -gq mouse-resize-pane on\; "
    cmd_byobu+="set-option -gq mouse-select-pane on\; "
    cmd_byobu+="set-option -gq mouse-select-window on\; "
    cmd_byobu+="set-window-option -gq mode-mouse on\; "
    cmd_byobu+="set-window-option -gq remain-on-exit off\; "
    tmux has-session -t $session &>/dev/null || cmd_byobu+="new-session -Ads $session\; "

    cmd="mkdir -p $logdir &>/dev/null;"
    cmd+="$cmd_byobu"
    [ -z $TMUX ] && cmd+="attach-session -t $session\; " || cmd+="switch-client -t $session\; "

    for tid in `seq 0 $((nthreads - 1))`; do
        [ $tid -ne 0 -a $((tid % 16)) -eq 0 ] && cmd+="; $cmd_byobu "
        if [ $threads_this -eq "${host_nthreads[$host_counter]}" ]; then
            ((host_counter++))
            host=${host_list[$host_counter]}
            threads_this=0
        fi
        if [ $threads_this -eq 0 ]; then
            [ $tid -ne 0 ] && cmd+="select-layout "$([ $w -le 0 ] && echo main-horizontal || echo tiled)"\; "
            cmd+="select-layout tiled\; "
            # run the daemon
            local pciaddr=${HOST_NIC[$host]}
            local core=$((HOST_NCORES[$host] - 1))
            local cmd_daemon="$TASVIR_BINDIR/tasvir_daemon --core %CORE% --pciaddr $pciaddr"$([ $tid -eq 0 ] && echo " --root")
            local tid2=$tid
            tid=d
            cmd_ssh=$([ $HOSTNAME != "$host" ] && echo "ssh -t $host")
            w=-1
            p=1
            window=$host-n$nthreads-$timestamp-$((++w))
            generate_cmd_thread $cmd_daemon
            cmd+="new-window -t $session -n $window $cmd_ssh '$cmd_thread'\; "
            cmd+="split-window -t $session:$window "
            tid=$tid2
            threads_this=1
        elif [ $((p % 3)) -eq 0 -a $w -eq 0 ]; then
            cmd+="select-layout main-horizontal\; "
            window=$host-$nthreads-$timestamp-$((++w))
            cmd+="new-window -t $session -n $window "
            p=0
        elif [ $((p % 4)) -eq 0 ]; then
            cmd+="select-layout tiled\; "
            window=$host-$nthreads-$timestamp-$((++w))
            cmd+="new-window -t $session -n $window "
            p=0
        else
            cmd+="split-window -t $session:$window "
        fi

        # run the worker
        generate_cmd_thread $cmd_app
        ((p++))
        cmd+="$cmd_ssh 'ulimit -c unlimited; sleep $delay; $cmd_thread'\; "
        ((threads_this++))
    done

    cmd+="select-layout "$([ $w -eq 0 ] && echo main-horizontal || echo tiled)"\; "
    cmd+="split-window -t $session:$window 'echo -e nthreads=$nthreads cmd_app=$cmd_app > $manifest' ;"

    cmd_prepare=
    for h in `seq 0 $host_counter`; do
        cmd_prepare+="ssh -t ${host_list[$h]} $RUNSCRIPT prepare; "
    done
    echo "$cmd_prepare $cmd"
}

setup_env() {
    # Timezone
    ln -fs /usr/share/zoneinfo/America/Los_Angeles /etc/localtime
    dpkg-reconfigure -f noninteractive tzdata

    # Upgrade
    apt-get update
    apt-get -y upgrade

    # Packages
    apt-get install -y \
        aptitude build-essential byobu clang clang-format clang-tidy cmake curl gdb git llvm-dev python3 python3-pip uthash-dev uuid-dev vim-nox
    byobu-enable-prompt

    # DPDK
    cat >/etc/sysctl.d/50-dpdk.conf <<EOF
    vm.nr_hugepages = 1050
EOF
    service procps restart
    cat >/etc/profile.d/dpdk.sh <<EOF
export RTE_ARCH=x86_64
export RTE_SDK=/opt/resq/nf/dpdk-v18.02
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

run_proxy() {
    type -t $1 | grep -q function
    if [ $? -eq 0 ]; then
        $1
    else
        for f in $TASVIR_CONFDIR/run*.conf; do
            . $f
        done
        local app_cmd=$1_cmd
        local hl=$1_host_list[@]
        local hn=$1_host_nthreads[@]
        local nt=$1_nthreads
        host_list=("${host_list[@]:-${!hl}}")
        host_nthreads=("${host_nthreads[@]:-${!hn}}")
        nthreads=${nthreads:-${!nt}}
        cmd=$(eval echo ${!app_cmd})
        eval $(generate_cmd $cmd)
    fi
}

declare -A HOST_NIC
declare -A HOST_NCORES

while read host ncores netdev; do
    HOST_NIC[$host]=$netdev
    HOST_NCORES[$host]=$ncores
done <<< $(grep -v '^#' $TASVIR_CONF | grep .)

IFS=' ' read -r -a host_list <<< "$host_list"
IFS=' ' read -r -a host_nthreads <<< "$host_nthreads"

if [ $# == 1 ]; then
    run_proxy $1
fi
