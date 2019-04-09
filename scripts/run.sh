#!/bin/bash

[[ "$TRACE"  ]] && set -x

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
DPDK_DRIVER=${DPDK_DRIVER:-igb_uio}
TASVIR_SRCDIR=$(realpath "$SCRIPTDIR/..")
TASVIR_CONFDIR=$TASVIR_SRCDIR/etc
TASVIR_CONF=$TASVIR_CONFDIR/tasvir.conf
TASVIR_BUILDDIR=$TASVIR_SRCDIR/build.$COMPILER
TASVIR_BINDIR=$TASVIR_BUILDDIR/bin
PIDFILE_PREFIX=/var/run/tasvir-
RTE_SDK=${RTE_SDK:-/srv/resq/nf/dpdk-v19.02}

prepare() {
    sync
    local nr_hugepages=1050
    echo never >/sys/kernel/mm/transparent_hugepage/enabled
    sysctl vm.nr_hugepages=$nr_hugepages &>/dev/null

    modprobe "$DPDK_DRIVER" &>/dev/null
    if [[ ${HOST_NIC[$HOSTNAME]} = *"bonding="*  ]]; then
        echo "${HOST_NIC[$HOSTNAME]}" | sed 's/slave=/\n/g' | sed 's/,.*//g' | grep ^0000: | while read -r i; do
            "$RTE_SDK/usertools/dpdk-devbind.py" --force -b "$DPDK_DRIVER" "$i" &>/dev/null
        done
    else
        "$RTE_SDK/usertools/dpdk-devbind.py" --force -b "$DPDK_DRIVER" "${HOST_NIC[$HOSTNAME]}" &>/dev/null
    fi

    for pidfile in "${PIDFILE_PREFIX}"*; do
        start-stop-daemon --stop --retry 3 --remove-pidfile --pidfile "$pidfile" &>/dev/null
    done
    rm -f /dev/shm/tasvir /dev/hugepages/tasvir* /var/run/.tasvir_config &>/dev/null

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
    # disable uncore frequency scaling
    wrmsr -a 0x620 0x1818
    pkill -f "tail.*-f.*.$HOSTNAME"
    mkdir "$LOGDIR" &>/dev/null
    while ! egrep -q "HugePages_Free:\s+$nr_hugepages" /proc/meminfo; do
        echo $HOSTNAME: Waiting for hugepages to be free
        sleep 2
    done
    service irqbalance stop

    sync
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
        local redirect
        if [ "$DEBUG" = 1 ]; then
            redirect="2>&1 | tee $logfile"
            local gdbcmds
            [ -f gdb.cmds ] && gdbcmds="--command gdb.cmds"
            cmd_worker="exec /usr/bin/taskset -c %CORE% gdb -ex run $gdbcmds --args stdbuf -o 0 -e 0 $* $redirect"
        else
            redirect=">$logfile 2>&1"
            cmd_worker="start-stop-daemon --background --start --make-pidfile --pidfile ${PIDFILE_PREFIX}%WID%.pid --startas "
            cmd_worker+="/bin/bash -- -c \"exec /usr/bin/taskset -c %CORE% stdbuf -o 0 -e 0 $* $redirect\";"
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

    local cmd
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
    local logdir="$LOGDIR/$host.$timestamp"
    local manifest="$logdir/manifest"
    local logfile="$logdir/t%WID%.%HOST%"
    local nr_worker_cur=0

    cmd="mkdir -p $logdir &>/dev/null;"
    cmd+="byobu "
    tmux has-session -t "$session" &>/dev/null || cmd+="new-session -Ads $session\\; "
    # [ -z $TMUX ] && cmd+="attach-session -t $session\\; " || cmd+="switch-client -t $session\\; "

    # wid: worker_id
    for wid in $(seq 0 $((nr_workers - 1))); do
        # move to the next host if numbers of workers reached the preset threshold
        if [ $nr_worker_cur -eq "${host_nr_workers[$host_counter]}" ]; then
            ((host_counter++))
            host=${host_list[$host_counter]}
            nr_worker_cur=0
            pane=0
        fi

        # create a new window for every 4 panes
        if [ $((pane % 4)) -eq 0 ]; then
            [ ! -z "$window" ] && cmd+="select-layout -t $session:$window tiled\\; "
            window=$host-n$nr_workers-t$timestamp-w$((window_idx++))
            cmd+="; byobu new-window -t $session -n $window "
            pane=0
        fi

        # run the daemon before the first worker
        if [ $nr_worker_cur -eq 0 ]; then
            local pciaddr=${HOST_NIC[$host]}
            local cmd_daemon
            core=$((HOST_NCORES[$host] - 1))
            cmd_daemon="$TASVIR_BINDIR/tasvir_daemon --core %CORE% --pciaddr $pciaddr"$([ "$wid" -eq 0 ] && echo " --root")
            local wid2=$wid
            wid=d
            cmd_ssh=$([ "$HOSTNAME" != "$host" ] && echo "ssh -tt $host")
            window_idx=0
            window=$host-n$nr_workers-t$timestamp-w$((window_idx++))
            generate_cmd_worker "$cmd_daemon"
            cmd+="$cmd_ssh '$cmd_worker'\\; "
            cmd+="select-pane -t $session:$window.0 -P 'bg=colour233'\\; "
            wid=$wid2
            nr_worker_cur=1
            pane=1
        fi

        # create a new pane
        if [ $((pane % 4)) -ne 0 ]; then
            cmd+="split-window -t $session:$window "
        fi

        # run the worker
        generate_cmd_worker "$cmd_app"
        ((pane++))
        cmd+="$cmd_ssh 'ulimit -c unlimited; sleep $delay; $cmd_worker'\\; "
        ((nr_worker_cur++))
    done

    cmd+="; sleep 0.5; byobu "
    cmd+="kill-window -t '$session:0'\\; "
    cmd+="select-layout -t '$session:$window' tiled\\; "
    window=${host_list[0]}-n$nr_workers-t$timestamp-w0
    cmd+="select-window -t '$session:$window'\\; "
    cmd+="select-pane -t '$session:$window.1'\\; "
    cmd+="resize-pane -Z -t '$session:$window.1'\\; "
    cmd+="set-option -t '$session' -q mouse-utf8 on\\; "
    cmd+="set-option -t '$session' -q mouse-resize-pane on\\; "
    cmd+="set-option -t '$session' -q mouse-select-pane on\\; "
    cmd+="set-option -t '$session' -q mouse-select-window on\\; "
    cmd+="set-option -t '$session' -q window-style 'bg=colour237'\\; "
    cmd+="set-option -t '$session' -q window-active-style 'bg=colour0'\\; "
    cmd+="set-window-option -t '$session' -q mode-mouse on\\; "
    cmd+="set-window-option -t '$session' -q remain-on-exit off\\; "
    cmd+="; echo -e nr_workers=$nr_workers cmd_app=$cmd_app > $manifest;"

    local cmd_prepare=
    for h in $(seq 0 $host_counter); do
        cmd_prepare+="ssh -tt ${host_list[$h]} $RUNSCRIPT prepare; "
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

    # Vim
    cat >/root/.vimrc.before.local <<EOF
let g:spf13_bundle_groups=['general', 'writing', 'programming', 'python', 'misc', 'youcompleteme']
let g:ycm_global_ycm_extra_conf = '~/.vim/.ycm_extra_conf.py'
colorscheme PaperColor
EOF
    cat >/root/.vimrc.bundles.local <<EOF
Bundle 'rhysd/vim-clang-format'
Bundle 'NLKNguyen/papercolor-theme'
EOF
    sh <(curl https://j.mp/spf13-vim3 -L)
    vim +BundleInstall! +BundleClean +q
    #cp /opt/.ycm_extra_conf.py /root/.vim/
    cd ~/.vim/bundle/YouCompleteMe || return
    YCM_CORES=1 python3 ./install.py --clang-completer --system-libclang
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
        local cmd
        local hl="$1_host_list[@]"
        local hn="$1_host_nr_workers[@]"
        local nt="$1_nr_workers"
        host_list=("${host_list[@]:-${!hl}}")
        host_nr_workers=("${host_nr_workers[@]:-${!hn}}")
        nr_workers=${nr_workers:-${!nt}}
        cmd_app=$(eval echo "${!cmd_app}")
        cmd=$(generate_cmd "$cmd_app")
        eval "$cmd"
    fi
}

declare -A HOST_NIC
declare -A HOST_NCORES

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
