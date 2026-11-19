#!/bin/bash
# Integration: first-SYN drop (Seawall proposal 0023) under floods.
#   - a UDP flood arms the gate, and first-SYN drop stays in standby;
#   - a SYN flood from spoofed sources on top engages it, and it stays
#     engaged while the flood lasts: counted before the filter, its own
#     drops keep it so;
#   - the flood over, it goes back to standby after clear_seconds;
#   - userspace stopped, no slot is cleared: SYNs pass, unfiltered, in
#     syn_guard_unready (fail-open);
#   - syn_guard = no: off, and a SYN flood from one address gets it
#     blocked, as before first-SYN drop.
# VG_HOOK=tc judges at TC ingress; VG_SYN_ATOMIC=0 takes the entries
# without atomic OR. Runs in private namespaces (t/bin/create_env.sh).
set -euo pipefail
. "$(dirname "$0")/../bin/create_env.sh"
BIN="$root/voidgate"
CTL="$root/voidgatectl"
CONF=$work/syn.conf
DAEMON_PID=
FLOODS=()

cleanup() {
    local p
    for p in "${FLOODS[@]}"; do
        kill "$p" 2>/dev/null || true
    done
    if [[ -n $DAEMON_PID ]]; then
        kill -CONT "$DAEMON_PID" 2>/dev/null || true
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

sysctl -qw net.ipv6.conf.peer0.disable_ipv6=1

# start <syn_guard> <threshold_pps>
start() {
    cat > "$CONF" <<EOF
interface = test0
xdp_mode = skb
wake_pps = 50
wake_mbps = 1000000
idle_poll_ms = 100
clear_seconds = 2
threshold_pps = $2
threshold_mbps = 1000000
metrics_port = 0
local_networks = 198.51.100.10/32
allow_ports = 22
syn_guard = $1
syn_guard_bits = 23
hook = ${VG_HOOK:-auto}
EOF
    # in the foreground the log is stderr
    "$BIN" -c "$CONF" 2>> "$work/syn.log" &
    DAEMON_PID=$!
    for _ in $(seq 50); do
        "$CTL" status >/dev/null 2>&1 && return
        sleep 0.1
    done
    fail "the daemon didn't start"
}

stop() {
    kill "$DAEMON_PID"
    wait "$DAEMON_PID" 2>/dev/null || true
    DAEMON_PID=
}

# flood <udp|syn|syn1> <seconds> <pps>, in the background: UDP from one
# address; SYNs from random spoofed addresses, random ports and sequence
# numbers; syn1, SYNs from one address
flood() {
    python3 - "$@" <<'PY' &
import os, random, socket, struct, sys, time

kind, secs, pps = sys.argv[1], float(sys.argv[2]), int(sys.argv[3])
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(("peer0", 0))
eth = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"

def cksum(b):
    n = sum(struct.unpack("!10H", b))
    n = (n >> 16) + (n & 0xffff)
    return ~(n + (n >> 16)) & 0xffff

def frame(src, l4, proto):
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0, 64,
                     proto, 0, src, socket.inet_aton("198.51.100.10"))
    ip = ip[:10] + struct.pack("!H", cksum(ip)) + ip[12:]
    return eth + ip + l4

end = time.time() + secs
gap = 1.0 / pps
t = time.time()
while t < end:
    if kind == "udp":
        f = frame(socket.inet_aton("198.51.100.1"),
                  struct.pack("!HHHH", 40000, 9, 8, 0), 17)
    else:
        src = (socket.inet_aton("203.0.113.66") if kind == "syn1"
               else os.urandom(4))
        tcp = struct.pack("!HHIIBBHHH", random.randint(1024, 65535), 80,
                          random.getrandbits(32), 0, 5 << 4, 0x02, 0, 0, 0)
        f = frame(src, tcp, 6)
    s.send(f)
    t += gap
    d = t - time.time()
    if d > 0:
        time.sleep(d)
PY
    FLOODS+=($!)
    LAST=$!
}

# word <name> <line>: its value
word() { tr ' ' '\n' <<< "$2" | sed -n "s/^$1=//p"; }

syn_state() { word syn_guard "$("$CTL" -r status)"; }

# every entry of the feed, oldest first
feed_all() {
    local epoch
    epoch=$("$CTL" -r feed | sed -n 's/^epoch=\([0-9a-f]*\) .*/\1/p')
    "$CTL" -r feed "$epoch" 0 | tail -n +2
}
counter() { word "$1" "$("$CTL" -r stats)"; }

fail() {
    echo "syn: $*"
    "$CTL" -r status 2>/dev/null || true
    "$CTL" -r stats 2>/dev/null || true
    echo "--- syn.log"
    cat "$work/syn.log"
    exit 1
}

start yes 1000000
[[ $(syn_state) == standby ]] || fail "expected standby at start"

# the thread that clears the filter blocks SIGTERM, which would otherwise
# set the stop flag without waking the main loop
blocked=0
for task in /proc/"$DAEMON_PID"/task/*; do
    mask=$(sed -n 's/^SigBlk:\t//p' "$task/status")
    (( 0x$mask & (1 << 14) )) && blocked=$((blocked + 1))
done
(( blocked == 1 )) || fail "expected one thread blocking SIGTERM, not $blocked"

# 1. a UDP flood arms the gate; first-SYN drop stays in standby. It goes
# on past the SYN flood, so the gate stays armed until step 3's standby
flood udp 13 1000
sleep 1
[[ $(word state "$("$CTL" -r status)") == active ]] \
    || fail "expected the UDP flood to arm the gate"
for _ in $(seq 5); do
    [[ $(syn_state) == standby ]] || fail "a UDP flood engaged first-SYN drop"
    sleep 0.1
done

# 2. a SYN flood on top engages it, and it stays engaged
# long enough for the samples below, however slow voidgatectl is under
# the floods
flood syn 8 1000
SYN=$LAST
sleep 0.5
[[ $(syn_state) == engaged ]] || fail "expected the SYN flood to engage it"
dropped=$(counter syn_guard_dropped)
for _ in $(seq 25); do
    [[ $(syn_state) == engaged ]] || fail "engaged went back to standby"
    sleep 0.1
done
(( $(counter syn_guard_dropped) > dropped )) || fail "expected first SYNs dropped"
feed_all \
    | grep -q ' kind=syn-engage source=self attack=1 syn_unproven_pps=[1-9]' \
    || fail "expected syn-engage in attack 1 on the feed"
[[ $(feed_all | grep -c ' kind=syn-engage ') == 1 ]] \
    || fail "expected one syn-engage: it went back and forth"
echo "engaged: $("$CTL" -r stats)"

# 3. the SYN flood over, standby after clear_seconds, the gate still armed
wait "$SYN"
sleep 1
[[ $(syn_state) == engaged ]] || fail "standby before clear_seconds"
sleep 1.5
STATUS=$("$CTL" -r status)
[[ $(word syn_guard "$STATUS") == standby ]] \
    || fail "expected standby after clear_seconds"
[[ $(word state "$STATUS") == active ]] \
    || fail "expected the gate still armed by the UDP flood"
feed_all | tail -1 \
    | grep -q ' kind=syn-standby source=self cause=quiet attack=1 ' \
    || fail "expected syn-standby in attack 1 on the feed"
wait "${FLOODS[@]}"
FLOODS=()

# 4. userspace stopped: no slot cleared, SYNs pass unfiltered
flood udp 8 1000
flood syn 8 1000
sleep 0.5
[[ $(syn_state) == engaged ]] || fail "expected engaged again"
unready=$(counter syn_guard_unready)
kill -STOP "$DAEMON_PID"
sleep 3
kill -CONT "$DAEMON_PID"
sleep 0.3
(( $(counter syn_guard_unready) > unready + 500 )) \
    || fail "expected SYNs passed unfiltered while userspace was stopped"
sleep 0.3
"$CTL" -r status \
    | grep -q '^WARNING: syn_guard: [0-9]* SYNs passed unfiltered' \
    || fail "expected status to warn of SYNs passed unfiltered"
echo "after the stop: $("$CTL" -r stats)"
wait "${FLOODS[@]}"
FLOODS=()
stop

# 5. syn_guard = no: off, and a source sending only SYNs is blocked
start no 100
[[ $(syn_state) == off ]] || fail "expected off with syn_guard = no"
flood udp 3 1000
flood syn1 3 500
sleep 2
"$CTL" -r blocks | grep -q 'cidr=203.0.113.66/32 ' \
    || fail "expected the SYN source blocked with syn_guard = no"
(( $(counter syn_unproven) == 0 )) || fail "syn_unproven counted when off"
wait "${FLOODS[@]}"
FLOODS=()

echo "syn test passed"
