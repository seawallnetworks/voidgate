#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Exercise real daemon startup in disposable mount, network and PID namespaces.
set -euo pipefail
. "$(dirname "$0")/../bin/create_env.sh"

directory=$(mktemp -d /tmp/voidgate-XXXXXX)
pid=

cleanup() {
    local result=$?
    trap - EXIT
    if [[ -n $pid ]]; then
        kill -TERM "$pid" 2>/dev/null || true
    fi
    if (( result != 0 )); then
        cat "$directory"/*.log "$directory"/*.err >&2 2>/dev/null || true
    fi
    cd /
    rm -rf -- "$directory"
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cd "$directory"
umask 022
cp "$root/t/conf/idle.conf" base.conf
mkdir "$work/log"
printf 'log_file = %s\n' "$work/log/voidgate.log" >> base.conf

status() {
    # the last line: without sw_flowd's table a CRITICAL line comes first
    [[ $(timeout 2 "$root/voidgatectl" -r status | tail -1) == state=idle* ]]
}

start_daemon() {
    timeout --kill-after=2 10 "$root/voidgate" -d "$@" \
        > launch.out 2> launch.err
    [[ ! -s launch.out ]]
    local message
    message=$(cat launch.err)
    [[ $message =~ ^voidgate\ daemon\ started\ \(pid\ ([0-9]+)\)$ ]]
    pid=${BASH_REMATCH[1]}
    kill -0 "$pid"
    [[ $(< /run/voidgate.pid) == "$pid" ]]
    status
    [[ $(readlink "/proc/$pid/fd/0") == /dev/null ]]
    [[ $(readlink "/proc/$pid/fd/1") == /dev/null ]]
    [[ $(readlink "/proc/$pid/cwd") == "$directory" ]]
    # Single fork + setsid: session leader, not the caller's session.
    # Linux stat: pid, comm, state, ppid, pgrp, session.
    local process comm state parent group session rest
    read -r process comm state parent group session rest < "/proc/$pid/stat"
    [[ $session == "$pid" ]]
    read -r process comm state parent group rest < /proc/self/stat
    [[ $group != "$session" ]]
}

stop_daemon() {
    "$root/voidgate" -s stop -c base.conf
    [[ ! -e /run/voidgate.sock && ! -e /run/voidgate-monitor.sock ]]
    [[ ! -e /run/voidgate.pid ]]
    # An XDP program must no longer be attached after socket removal.
    [[ $(ip -details link show test0) != *prog/xdp* ]]
    pid=
}

expect_failure() {
    local result=0
    timeout --kill-after=2 10 "$@" > failure.out 2> failure.err || result=$?
    [[ $result == 1 ]]
    [[ ! -e /run/voidgate.sock ]]
    [[ $(ip -details link show test0) != *prog/xdp* ]]
}

expect_failure "$root/voidgate" -s stop -c base.conf

# Default daemon log, permissions and append across restarts.
start_daemon -c base.conf
[[ $(readlink "/proc/$pid/fd/2") == "$work/log/voidgate.log" ]]
[[ $(stat -c %a "$work/log/voidgate.log") == 644 ]]
stop_daemon
printf 'append marker\n' >> "$work/log/voidgate.log"
start_daemon -c base.conf
grep -q 'append marker' "$work/log/voidgate.log"
stop_daemon

# Configured relative destination, verbosity and relative config reload.
cp base.conf run.conf
printf 'log_file = config.log\n' >> run.conf
start_daemon -c run.conf -vv
[[ $(readlink "/proc/$pid/fd/2") == "$directory/config.log" ]]
grep -q 'active configuration' config.log
printf 'log_file = changed.log\n' >> run.conf
[[ $("$root/voidgatectl" reload) == ok ]]
[[ ! -e changed.log ]]
grep -q 'reloaded run.conf' config.log
stop_daemon

# reload lifts blocks that now cover a local or allow-listed prefix; others
# stay.
cp base.conf reload.conf
start_daemon -c reload.conf
[[ $("$root/voidgatectl" block 203.0.113.0/24) == ok ]]
[[ $("$root/voidgatectl" block 192.0.2.0/24) == ok ]]
[[ $("$root/voidgatectl" block 198.18.0.0/24) == ok ]]
printf 'local_networks = 198.51.100.10/32, 203.0.113.5/32\n' >> reload.conf
printf 'allow_networks = 192.0.2.99/32\n' >> reload.conf
[[ $("$root/voidgatectl" reload) == ok ]]
mapfile -t lines < <("$root/voidgatectl" -r blocks)
[[ ${lines[0]} =~ \ n=1\ next=end$ ]]
[[ ${lines[1]} =~ ^id=[0-9]+\ cidr=198\.18\.0\.0/24\ reason=manual\  ]]
grep -q 'reload: unblock 203.0.113.0/24' "$work/log/voidgate.log"
grep -q 'reload: unblock 192.0.2.0/24' "$work/log/voidgate.log"
stop_daemon

# -g hands the control socket to that group; reload keeps it.
# An unknown group stops the start.
start_daemon -c base.conf -g nogroup
[[ $(stat -c '%a %G' /run/voidgate.sock) == '660 nogroup' ]]
[[ $("$root/voidgatectl" block 198.18.0.1/32 ttl=60) == ok ]]
[[ $("$root/voidgatectl" -r blocks | tail -1) =~ ^id=[0-9]+\ cidr=198\.18\.0\.1/32\ reason=timed\  ]]
[[ $("$root/voidgatectl" reload) == ok ]]
[[ $(stat -c %G /run/voidgate.sock) == nogroup ]]
# An error reply is a failed command (exit status 1).
result=0
"$root/voidgatectl" block 127.0.0.1/32 ttl=60 > refused.out || result=$?
[[ $result == 1 && $(< refused.out) == 'error: refused or map update failed' ]]
"$root/voidgatectl" unblock 198.18.0.1/32 > /dev/null
stop_daemon
# Before the fork: the caller sees why, and nothing is left behind.
expect_failure "$root/voidgate" -d -c base.conf -g no-such-voidgate-group
grep -q 'no group "no-such-voidgate-group" in /etc/group' failure.err
[[ ! -e /run/voidgate.pid ]]
# Without -g the socket is root's alone.
start_daemon -c base.conf
[[ $(stat -c '%a %G' /run/voidgate.sock) == '660 root' ]]
stop_daemon

# -R: the read-only socket (Seawall proposal 0012 §2), for its group. It
# answers status, stats, feed and blocks, and refuses the rest.
# Each change says whose it is: a socket caller's uid, or voidgate's own.
# -r: the daemon's answers, not voidgatectl's tables.
ro() { "$root/voidgatectl" -r -s /run/voidgate-monitor.sock "$@"; }
as_nobody() { setpriv --reuid=nobody --regid=nogroup --clear-groups "$@"; }
cp base.conf ro.conf
printf 'drop_map_size = 512\n' >> ro.conf
start_daemon -c ro.conf -g nogroup -R nogroup
[[ $(stat -c '%a %U %G' /run/voidgate-monitor.sock) == '660 root nogroup' ]]
[[ $(ro status | tail -1) == state=idle* ]]
[[ $(ro stats) == rx_pkts=* ]]
[[ $(ro blocks) =~ \ n=0\ next=end$ ]]
[[ $("$root/voidgatectl" -s /run/voidgate-monitor.sock blocks) == '(none)' ]]
for command in arm disarm reload 'block 198.18.0.9/32' 'unblock 198.18.0.9/32'; do
    result=0
    ro $command > ro.out || result=$?
    [[ $result == 1 && $(< ro.out) == 'error: read-only socket' ]]
done
[[ $(ro status | tail -1) == state=idle* ]]
result=0
ro feedx > ro.out || result=$?
[[ $result == 1 && $(< ro.out) == 'error: unknown command' ]]
# the old names are gone
for command in drops 'drop 198.18.0.9/32' 'undrop 198.18.0.9/32'; do
    result=0
    "$root/voidgatectl" $command > ro.out || result=$?
    [[ $result == 1 && $(< ro.out) == 'error: unknown command' ]]
done

cursor=$(ro feed)
[[ $cursor =~ ^epoch=([0-9a-f]{16})\ seq=0\ oldest=1\ gap=0\ n=0\ more=0$ ]]
epoch=${BASH_REMATCH[1]}
# a block by uid 0 arms the gate: both its own; one by nobody, its uid
[[ $("$root/voidgatectl" block 198.18.0.1/32) == ok ]]
[[ $(as_nobody "$root/voidgatectl" block 198.18.0.2/32 ttl=60) == ok ]]
ro feed "$epoch" 0 > feed.out
mapfile -t lines < feed.out
[[ ${lines[0]} == "epoch=$epoch seq=3 oldest=1 gap=0 n=3 more=0" ]]
[[ ${lines[1]} =~ ^seq=1\ time=[0-9]{13}\ kind=arm\ source=socket\ uid=0\ cause=manual-block$ ]]
[[ ${lines[2]} =~ ^seq=2\ time=[0-9]+\ kind=block\ source=socket\ uid=0\ id=1\ cidr=198\.18\.0\.1/32\ reason=manual\ expires=0$ ]]
[[ ${lines[3]} =~ ^seq=3\ time=[0-9]+\ kind=block\ source=socket\ uid=65534\ id=2\ cidr=198\.18\.0\.2/32\ reason=timed\ expires=[0-9]{10}$ ]]
# nothing new; another epoch, or a cursor not reached yet, is a gap
[[ $(ro feed "$epoch" 3) == "epoch=$epoch seq=3 oldest=1 gap=0 n=0 more=0" ]]
[[ $(ro feed 0000000000000001 2) == "epoch=$epoch seq=3 oldest=1 gap=1 n=0 more=0" ]]
[[ $(ro feed "$epoch" 9) == "epoch=$epoch seq=3 oldest=1 gap=1 n=0 more=0" ]]
result=0
ro feed "$epoch" > ro.out || result=$?
[[ $result == 1 && $(< ro.out) == 'error: usage: feed <epoch> <seq>' ]]

ro blocks > blocks.out
mapfile -t lines < blocks.out
[[ ${lines[0]} == "epoch=$epoch seq=3 n=2 next=end" ]]
[[ ${lines[1]} =~ ^id=1\ cidr=198\.18\.0\.1/32\ reason=manual\ inserted=[0-9]{10}\ expires=0$ ]]
[[ ${lines[2]} =~ ^id=2\ cidr=198\.18\.0\.2/32\ reason=timed\ inserted=[0-9]+\ expires=[0-9]{10}$ ]]
[[ $(ro blocks after 1 | head -1) == "epoch=$epoch seq=3 n=1 next=end" ]]
[[ $(ro blocks after 2) == "epoch=$epoch seq=3 n=0 next=end" ]]

# 300 blocks: two pages, then the end
for i in $(seq 0 1 297); do
    printf 'block 198.19.%d.%d/32\n' $((i / 250)) $((i % 250))
done | while read -r line; do
    "$root/voidgatectl" $line > /dev/null
done
first=$(ro blocks | head -1)
[[ $first =~ ^epoch=$epoch\ seq=[0-9]+\ n=256\ next=([0-9]+)$ ]]
next=${BASH_REMATCH[1]}
[[ $(ro blocks after "$next" | head -1) =~ ^epoch=$epoch\ seq=[0-9]+\ n=44\ next=end$ ]]
# voidgatectl's table reads both pages: a header and the 300
"$root/voidgatectl" -s /run/voidgate-monitor.sock blocks > table.out
[[ $(wc -l < table.out) == 301 ]]
[[ $(head -1 table.out) =~ ^\ *id\ +cidr\ +reason\ +since\ +expires$ ]]
[[ $(sed -n 2p table.out) =~ ^\ *1\ +198\.18\.0\.1/32\ +manual\ +[-0-9]{10}\ [:0-9]{8}\ +never$ ]]

# unblock and disarm, by the caller; then a reload
[[ $("$root/voidgatectl" unblock 198.18.0.1/32) == ok ]]
[[ $(as_nobody "$root/voidgatectl" disarm) == ok ]]
[[ $("$root/voidgatectl" reload) == ok ]]
ro feed "$epoch" 301 > feed.out
mapfile -t lines < feed.out
[[ ${lines[0]} == "epoch=$epoch seq=304 oldest=1 gap=0 n=3 more=0" ]]
[[ ${lines[1]} =~ kind=unblock\ source=socket\ uid=0\ cause=unblock\ id=1\ cidr=198\.18\.0\.1/32 ]]
[[ ${lines[2]} =~ kind=disarm\ source=socket\ uid=65534\ cause=command$ ]]
[[ ${lines[3]} =~ kind=reload\ source=socket\ uid=0\ cause=reload$ ]]
grep -q 'disarmed (command, socket uid 65534)' "$work/log/voidgate.log"
[[ $(ro blocks) == "epoch=$epoch seq=304 n=0 next=end" ]]
stop_daemon

# -B: the ban socket, for its group: block <address> ttl=N only, one
# address (/32, /128 or bare), never a network. A block on an idle gate
# arms it, both changes the ban client's, source ban.
start_daemon -c ro.conf -g root -R nogroup -B nogroup
[[ $(stat -c '%a %U %G' /run/voidgate-ban.sock) == '660 root nogroup' ]]
for command in status stats feed blocks arm disarm reload \
    'block 198.18.0.9/32' 'block 198.18.0.9/32 ttl=0' \
    'block 198.18.0.9/32 ttl=60 x' 'unblock 198.18.0.9/32' \
    'block 198.18.0.0/24 ttl=60' 'block 0.0.0.0/1 ttl=60' \
    'block 2001:db8::/64 ttl=60' 'block bad ttl=60'; do
    result=0
    as_nobody "$root/voidgatectl" -r -s /run/voidgate-ban.sock $command \
        > ban.out || result=$?
    [[ $result == 1 && $(< ban.out) == 'error: denied: the ban socket takes only block <address> ttl=<seconds>' ]]
done
[[ $(ro status | tail -1) == state=idle* ]]
[[ $(as_nobody "$root/voidgatectl" -s /run/voidgate-ban.sock block 198.18.0.3/32 ttl=60) == ok ]]
ro feed > ban.out
[[ $(< ban.out) =~ ^epoch=([0-9a-f]{16})\ seq=2 ]]
ro feed "${BASH_REMATCH[1]}" 0 > feed.out
mapfile -t lines < feed.out
[[ ${lines[1]} =~ ^seq=1\ time=[0-9]+\ kind=arm\ source=ban\ uid=65534\ cause=ban$ ]]
[[ ${lines[2]} =~ ^seq=2\ time=[0-9]+\ kind=block\ source=ban\ uid=65534\ id=1\ cidr=198\.18\.0\.3/32\ reason=timed ]]
grep -q 'armed (ban, ban uid 65534)' "$work/log/voidgate.log"
# a bare address, and IPv6's /128
[[ $(as_nobody "$root/voidgatectl" -s /run/voidgate-ban.sock block 198.18.0.4 ttl=60) == ok ]]
[[ $(as_nobody "$root/voidgatectl" -s /run/voidgate-ban.sock block 2001:db8::4/128 ttl=60) == ok ]]
[[ $(ro blocks | head -1) =~ \ n=3\ next=end$ ]]
stop_daemon
[[ ! -e /run/voidgate-ban.sock ]]

# The XDP attach is tried quietly (a race with mfwd's is retried and
# works), but a real refusal still logs the kernel's reason: a dummy
# interface's driver has no native XDP, so auto falls back to skb.
ip link add dum0 type dummy
ip link set dum0 up
sed 's/^xdp_mode = .*/xdp_mode = auto/' base.conf > auto.conf
: > "$work/log/voidgate.log"
start_daemon -c auto.conf -i dum0
grep -q 'libbpf: .*Kernel error message' "$work/log/voidgate.log"
grep -q 'native XDP attach failed (.*), falling back to skb' \
    "$work/log/voidgate.log"
[[ $("$root/voidgatectl" -r status | tail -1) == *hook=xdp-skb* ]]
stop_daemon
ip link del dum0

# A restart draws another epoch.
start_daemon -c base.conf -R nogroup
[[ $(ro feed) =~ ^epoch=([0-9a-f]{16})\ seq=0 ]]
[[ ${BASH_REMATCH[1]} != "$epoch" ]]
stop_daemon
# An unknown group stops the start, and leaves neither socket.
expect_failure "$root/voidgate" -d -c base.conf -R no-such-voidgate-group
grep -q 'no group "no-such-voidgate-group" in /etc/group' failure.err
[[ ! -e /run/voidgate-monitor.sock && ! -e /run/voidgate.pid ]]

# Append mode preserves existing contents.
cp base.conf append.conf
printf 'log_file = append.log\n' >> append.conf
printf 'append marker\n' > append.log
start_daemon -c append.conf
[[ $(readlink "/proc/$pid/fd/2") == "$directory/append.log" ]]
grep -q 'append marker' append.log
stop_daemon

# Foreground remains attached to the launched PID and logs to stderr, as
# under the unit, whatever log_file says: that is -d's.
cp base.conf foreground.conf
printf 'log_file = foreground-config.log\n' >> foreground.conf
"$root/voidgate" -c foreground.conf 2> foreground.err &
pid=$!
for attempt in {1..100}; do
    if status 2>/dev/null; then
        break
    fi
    sleep 0.05
done
status
[[ $(readlink "/proc/$pid/fd/2") == "$directory/foreground.err" ]]
grep -q 'idle on test0' foreground.err
[[ ! -e foreground-config.log ]]
stop_daemon

# A second instance must fail without touching the first one's socket,
# XDP program or pid file.
start_daemon -c base.conf
first=$pid

second_instance() {
    local result=0
    timeout --kill-after=2 10 "$root/voidgate" -d "$@" \
        > second.out 2> second.err || result=$?
    [[ $result == 1 ]]
    kill -0 "$first"
    [[ $(< /run/voidgate.pid) == "$first" ]]
    [[ -S /run/voidgate.sock ]]
    status
    [[ $(ip -details link show test0) == *prog/xdp* ]]
}

second_instance -c base.conf
grep -q "already running (pid $first, /run/voidgate.pid)" second.err
# Another pid file does not help: the control socket is still in use.
cp base.conf other-pid.conf
printf 'pid_file = %s\n' "$directory/other.pid" >> other-pid.conf
second_instance -c other-pid.conf
grep -q 'already serving /run/voidgate.sock' second.err
[[ ! -e other.pid ]]
stop_daemon

# After a crash the pid file, socket file and XDP program are left behind,
# but the lock died with the process: a restart must take over cleanly.
start_daemon -c base.conf
kill -KILL "$pid"
while kill -0 "$pid" 2>/dev/null; do
    sleep 0.05
done
[[ -e /run/voidgate.pid && -S /run/voidgate.sock ]]
start_daemon -c base.conf
stop_daemon

# A stale pid file (no daemon holds its lock) must not signal that pid.
sleep 60 &
bystander=$!
printf '%s\n' "$bystander" > /run/voidgate.pid
result=0
"$root/voidgate" -s stop -c base.conf 2> stale.err || result=$?
[[ $result == 1 ]]
grep -q 'not running' stale.err
kill -0 "$bystander"
[[ ! -e /run/voidgate.pid ]]
kill "$bystander"
wait "$bystander" 2>/dev/null || true

# Fail before forking for bad config and unusable/invalid log paths.
cp base.conf invalid.conf
printf 'wake_pps = invalid\n' >> invalid.conf
expect_failure "$root/voidgate" -d -c invalid.conf
cp base.conf missing.conf
printf 'log_file = missing/daemon.log\n' >> missing.conf
expect_failure "$root/voidgate" -d -c missing.conf
printf -v oversized '%0256d' 0
cp base.conf invalid.conf
printf 'log_file = %s\n' "$oversized" >> invalid.conf
expect_failure "$root/voidgate" -d -c invalid.conf

# Fail after forking: no capabilities means BPF initialization must fail.
cp base.conf bpf.conf
printf 'log_file = bpf-failure.log\n' >> bpf.conf
expect_failure setpriv --bounding-set=-all "$root/voidgate" \
    -d -c bpf.conf
grep -q 'daemon startup failed' failure.err
grep -q 'attach failed' bpf-failure.log

# No live daemon may remain after any failure (allow exited zombies).
for entry in /proc/[0-9]*/stat; do
    if read -r process comm state rest < "$entry"; then
        [[ $comm != '(voidgate)' || $state == Z ]]
    fi
done
echo "Daemon integration tests passed"
