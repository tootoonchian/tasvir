#!/bin/bash

[[ "$TRACE"  -eq 1 ]] && set -x

COMPILER=${COMPILER:-gcc}
if [[ "$COMPILER" == gcc ]]; then
    export CC=$(command -v gcc)
    export CXX=$(command -v g++)
elif [[ "$COMPILER" == clang ]]; then
    export CC=$(command -v clang)
    export CXX=$(command -v clang++)
else
    echo 'COMPILER must be gcc or clang'
    exit 1
fi
RUNSCRIPT=$(realpath "${BASH_SOURCE[0]}")
SCRIPTDIR=$(dirname "$RUNSCRIPT")
LOGDIR=$SCRIPTDIR/log
DPDK_DRIVER=${DPDK_DRIVER:-vfio-pci}
TASVIR_SRCDIR=$(realpath "$SCRIPTDIR/..")
TASVIR_CONFDIR=$TASVIR_SRCDIR/etc
TASVIR_CONF=$TASVIR_CONFDIR/tasvir.conf
TASVIR_BUILDDIR=$TASVIR_SRCDIR/build.$COMPILER
TASVIR_BINDIR=$TASVIR_BUILDDIR/bin
PIDFILE_PREFIX=/var/run/tasvir-
DPDK_INIT=$(test -z "$RTE_SDK" && echo 1 || echo 0)
RTE_SDK=${RTE_SDK:-$TASVIR_SRCDIR/third_party/dpdk}
RTE_TARGET=${RTE_TARGET:-x86_64-native-linuxapp-gcc}

nr_hugepages=1050

prepare() {
    sync
    ## cleanup after a previous run
    for pidfile in "${PIDFILE_PREFIX}"*; do
        start-stop-daemon --stop --retry 3 --remove-pidfile --pidfile "$pidfile" &>/dev/null
    done
    rm -f /dev/shm/tasvir /dev/hugepages/tasvir* /var/run/.tasvir_config &>/dev/null

    sysctl vm.nr_hugepages=$nr_hugepages &>/dev/null
    pkill -f "tail.*-f.*.$HOSTNAME"
    mkdir "$LOGDIR" &>/dev/null
    while ! egrep -q "HugePages_Free:\s+$nr_hugepages" /proc/meminfo; do
        echo $HOSTNAME: Waiting for hugepages to be free
        sleep 2
    done

    ## load dpdk driver and bind the relevant NIC
    modprobe "$DPDK_DRIVER" &>/dev/null
    if [[ ${HOST_NIC[$HOSTNAME]} = *"bonding="*  ]]; then
        echo "${HOST_NIC[$HOSTNAME]}" | sed 's/slave=/\n/g' | sed 's/,.*//g' | grep ^0000: | while read -r i; do
            driverctl set-override "$i" "$DPDK_DRIVER" &>/dev/null
        done
    else
        driverctl set-override "${HOST_NIC[$HOSTNAME]}" "$DPDK_DRIVER" #&>/dev/null
    fi

    ## improve reproducibility
    service irqbalance stop
    # echo 1 > /proc/sys/kernel/randomize_va_space
    echo 1 > /sys/module/processor/parameters/ignore_ppc
    echo 0 > /proc/sys/kernel/nmi_watchdog
    [ -f /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq ] && max_freq=$(cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq)
    for cpu in /sys/devices/system/cpu/cpu[0-9]*; do
        # fix core frequency
        if [ -d "$cpu/cpufreq" ]; then
            echo performance > "$cpu/cpufreq/scaling_governor"
            # echo "$max_freq" > "$cpu/cpufreq/scaling_setspeed"
            echo "$max_freq" > "$cpu/cpufreq/scaling_min_freq"
            echo "$max_freq" > "$cpu/cpufreq/scaling_max_freq"
        fi
        # disable c states
        if [ -d "$cpu/cpuidle" ]; then
            for state_disable in "$cpu"/cpuidle/state[1-9]/disable; do
                echo 1 > "$state_disable"
            done
        fi
        # disable p states
        if [ -d /sys/devices/system/cpu/intel_pstate ]; then
            echo 0 > /sys/devices/system/cpu/intel_pstate/hwp_dynamic_boost
            echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo
            echo 100 > /sys/devices/system/cpu/intel_pstate/min_perf_pct
            echo 100 > /sys/devices/system/cpu/intel_pstate/max_perf_pct
        fi
    done &>/dev/null
    [ -f /sys/devices/system/cpu/cpufreq/boost ] && echo 0 > /sys/devices/system/cpu/cpufreq/boost
    modprobe msr
    wrmsr -a 0x620 0x1d1d # disable uncore frequency scaling
    # wrmsr -a 0x1a4 0x0 # enable prefetchers

    # tph is bad for reproducibility but experimentally here for RO/RW mappings
    echo madvise >/sys/kernel/mm/transparent_hugepage/enabled
    echo madvise >/sys/kernel/mm/transparent_hugepage/defrag
    echo advise >/sys/kernel/mm/transparent_hugepage/shmem_enabled

    date > /tmp/prepare.done
}

compile() {
    mkdir "$TASVIR_BUILDDIR" &>/dev/null
    cd "$TASVIR_BUILDDIR" || return
    local build_system
    local build_cmd=make
    if command -v ninja &>/dev/null; then
        build_system="-GNinja"
        build_cmd=ninja
    fi
    cmake $build_system .. && $build_cmd || exit 1
}

generate_cmd() {
    generate_cmd_worker() {
        local pidfile=${PIDFILE_PREFIX}%WID%.pid
        local env="TASVIR_CORE=%CORE%"
        if [ "$DEBUG" = 1 ]; then
            local gdbcmd="gdb -q -ex set\ pagination\ off -ex run "
            [ -f gdb.cmds ] && gdbcmd+="--command gdb.cmds "
            gdbcmd+="--args"
            cmd_worker="echo \$\$ > $pidfile; "
            cmd_worker+="/usr/bin/script -f -c \"$env exec /usr/bin/numactl -a -l -C %CORE% $gdbcmd $*\" $logfile"
        else
            cmd_worker="start-stop-daemon --background --start --make-pidfile --pidfile $pidfile --startas "
            cmd_worker+="/usr/bin/script -- -f -c \"$env exec /usr/bin/numactl -a -l -C %CORE% $*\" $logfile; "
            #[ $wid = d -o $wid = 0 ] && \
            cmd_worker+="sleep 0.1; stdbuf -o 0 -e 0 tail -n 1000 -f $logfile"
        fi
        cmd_worker=$(echo "$cmd_worker" | sed -e "s/%CORE%/$core/g" -e "s/%WID%/$wid/g" -e "s/%NR_WORKERS%/$nr_workers/g" -e "s/%HOST%/$host/g")
        ((core--))
    }

    local nr_workers=${nr_workers:-1}
    local delay=${delay:-0.3}

    local host_counter=0
    local host_list=("${host_list[@]:-${!HOST_NCORES[@]}}")
    local host=${host_list[0]}

    declare -g cmd
    local cmd_app="$*"
    local cmd_ssh
    local cmd_worker
    local core
    local session=tasvir_run_$host
    local pane=0
    local timestamp
    timestamp=$(date +"%Y%m%d_%H%M%S")
    local window
    local window_idx=0
    declare -g logdir="$LOGDIR/$host.$timestamp"
    local manifest="$logdir/manifest"
    local logfile="$logdir/t%WID%.%HOST%"
    local nr_worker_cur=0

    cmd="mkdir -p $logdir &>/dev/null; "
    cmd+="tmux has-session -t '$session' &>/dev/null || byobu new-session -Ads '$session' "

    local wid # worker_id
    for wid in $(seq 0 $((nr_workers - 1))); do
        # move to the next host if numbers of workers reached the preset threshold
        if [ $nr_worker_cur -eq "${host_nr_workers[$host_counter]}" ]; then
            ((host_counter++))
            host=${host_list[$host_counter]}
            nr_worker_cur=0
            pane=0
            window_idx=0
        fi

        # create a new window for every 4 panes
        if [ $((pane % 4)) -eq 0 ]; then
            [ ! -z "$window" ] && cmd+="select-layout -t '$session:$window' tiled\\; "
            window=$host-n$nr_workers-t$timestamp-w$((window_idx++))
            cmd+="; byobu new-window -t '$session' -n '$window' "
            pane=0
        fi

        # run the daemon before the first worker
        if [ $nr_worker_cur -eq 0 ]; then
            local pciaddr=${HOST_NIC[$host]}
            local cmd_daemon
            local is_root=$(expr "$wid" = 0)
            core=$((HOST_NCORES[$host] - 1))
            cmd_daemon="/usr/bin/env TASVIR_IS_ROOT=$is_root TASVIR_CORE=%CORE% TASVIR_PCIADDR=$pciaddr $TASVIR_BINDIR/tasvir_daemon"
            local wid2=$wid
            wid=d
            cmd_ssh=$([ "$HOSTNAME" != "$host" ] && echo "ssh -o LogLevel=QUIET -tt $host")
            generate_cmd_worker "$cmd_daemon"
            cmd+="$cmd_ssh '$cmd_worker'\\; "
            cmd+="select-pane -t '$session:$window.0' -P 'bg=colour233'\\; "
            wid=$wid2
            nr_worker_cur=1
            pane=1
        fi

        # create a new pane
        [ $((pane % 4)) -ne 0 ] && cmd+="split-window -t '$session:$window' "
        # [ $((pane % 4)) -ne 0 ] && cmd+="new-window -t '$session' "

        # run the worker
        generate_cmd_worker "$cmd_app"
        ((pane++))
        cmd+="$cmd_ssh 'ulimit -c unlimited; sleep $delay; $cmd_worker'\\; "
        ((nr_worker_cur++))
    done

    cmd+="; sleep 0.5; byobu "
    # cmd+="kill-window -t '$session:0'\\; "
    cmd+="select-layout -t '$session:$window' tiled\\; "
    window=${host_list[0]}-n$nr_workers-t$timestamp-w0
    cmd+="select-window -t '$session:$window'\\; "
    cmd+="select-pane -t '$session:$window.1'\\; "
    [ ! -z $ZOOM_WID0 ] && cmd+="resize-pane -Z -t '$session:$window.1'\\; "
    cmd+="set-option -t '$session' -q mouse-utf8 on\\; "
    cmd+="set-option -t '$session' -q mouse-resize-pane on\\; "
    cmd+="set-option -t '$session' -q mouse-select-pane on\\; "
    cmd+="set-option -t '$session' -q mouse-select-window on\\; "
    cmd+="set-option -t '$session' -q window-style 'bg=colour237'\\; "
    cmd+="set-option -t '$session' -q window-active-style 'bg=colour0'\\; "
    cmd+="set-window-option -t '$session' -q mode-mouse on\\; "
    cmd+="set-window-option -t '$session' -q remain-on-exit off\\; "
    # [ -z $TMUX ] && cmd+="attach-session -t $session\\; " || cmd+="switch-client -t $session\\; "
    cmd+="; echo -e nr_workers=$nr_workers cmd_app=$cmd_app > $manifest; "

    local cmd_prepare=
    for h in $(seq 0 $host_counter); do
        cmd_prepare+="ssh -o LogLevel=QUIET -tt ${host_list[$h]} $RUNSCRIPT prepare; "
    done
    cmd="$cmd_prepare $cmd"
}

setup() {
    apt -y install byobu clang cmake curl driverctl gdb ninja uthash-dev
    if [ "$DPDK_INIT" -eq 1 ]; then
        cd /tmp
        curl -LO https://git.dpdk.org/dpdk/snapshot/dpdk-19.08.tar.gz
        mkdir -p $RTE_SDK &>/dev/null
        tar xfz dpdk-19.08.tar.gz -C $RTE_SDK --strip-components 1
        cd $RTE_SDK
        make -j install T=$RTE_TARGET
        cat >/etc/sysctl.d/50-dpdk.conf <<EOF
vm.nr_hugepages = $nr_hugepages
EOF
        service procps restart
    fi
}

run_proxy() {
    if type -t "$1" | grep -q function; then
        $1
    else
        for f in "$TASVIR_CONFDIR"/run*.conf; do
            # shellcheck source=/dev/null
            . "$f"
        done
        local cmd_app="$1_cmd"
        local hl="$1_host_list[@]"
        local hn="$1_host_nr_workers[@]"
        local nt="$1_nr_workers"
        host_list=("${host_list[@]:-${!hl}}")
        host_nr_workers=("${host_nr_workers[@]:-${!hn}}")
        nr_workers=${nr_workers:-${!nt}}
        cmd_app=$(eval echo "${!cmd_app}")
        generate_cmd "$cmd_app"
        echo logdir=$logdir
        eval "$cmd"
    fi
}

declare -gA HOST_NIC
declare -gA HOST_NCORES

while read -r host ncores netdev; do
    HOST_NIC["$host"]="$netdev"
    HOST_NCORES["$host"]="$ncores"
done <<< "$(grep -v "^#" "$TASVIR_CONF" | grep .)"

# convert $host_list and $host_nr_workers into arrays
IFS=' ' read -r -a host_list <<< "${host_list}"
IFS=' ' read -r -a host_nr_workers <<< "${host_nr_workers}"

if [ $# == 1 ]; then
    run_proxy "$1"
fi
