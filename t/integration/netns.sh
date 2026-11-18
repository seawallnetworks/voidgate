#!/bin/bash
# Integration: veth pair, daemon starts IDLE, flood wakes it, block works;
# each flood is an attack, in the feed and status (Seawall proposal 0017):
# one a disarm ends, one that ends quiet on a gate its blocks keep armed.
# VG_HOOK=tc judges at TC ingress. Runs in private namespaces
# (t/bin/create_env.sh), so a running voidgate is never reached.
set -euo pipefail
. "$(dirname "$0")/../bin/create_env.sh"
BIN="$root/voidgate"
CTL="$root/voidgatectl"
CONF=$work/netns.conf
NS=peer
DAEMON_PID=
cleanup() {
  [[ -n $DAEMON_PID ]] && kill "$DAEMON_PID" 2>/dev/null || true
  ip netns del "$NS" 2>/dev/null || true
}
trap cleanup EXIT

cat > "$CONF" <<EOF
interface = test0
xdp_mode = skb
wake_pps = 50
wake_mbps = 1000
idle_poll_ms = 200
clear_seconds = 2
threshold_pps = 20
threshold_mbps = 1000
ban_time = 60
aggregate_k = 8
local_networks =
allow_ports = 22
metrics_port = 0
hook = ${VG_HOOK:-auto}
EOF

# The flood comes from a namespace of its own, over the veth: sent from
# this one, traffic to a local address would take lo.
ip netns add "$NS"
ip link set peer0 netns "$NS"
ip addr add 198.51.100.10/24 dev test0
ip netns exec "$NS" ip addr add 198.51.100.1/24 dev peer0
ip netns exec "$NS" ip link set peer0 up
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ping -c 1 -W 1 198.51.100.10 >/dev/null || true

# in the foreground the log is stderr
"$BIN" -c "$CONF" 2> "$work/voidgate.log" &
DAEMON_PID=$!
for _ in $(seq 50); do
  "$CTL" status >/dev/null 2>&1 && break
  sleep 0.1
done
STATUS=$("$CTL" -r status || true)
echo "initial: $STATUS"
echo "$STATUS" | grep -q 'state=idle' || { echo "expected idle"; exit 1; }

flood() {
  ip netns exec "$NS" python3 - <<'PY'
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
end = time.time() + 2
n = 0
while time.time() < end:
    s.sendto(b"x"*64, ("198.51.100.10", 9))
    n += 1
s.close()
print("sent", n)
PY
}

# every entry of the feed, oldest first
feed_all() {
  local epoch
  epoch=$("$CTL" -r feed | sed -n 's/^epoch=\([0-9a-f]*\) .*/\1/p')
  "$CTL" -r feed "$epoch" 0 | tail -n +2
}

# word <name> <line>: its value
word() { tr ' ' '\n' <<< "$2" | sed -n "s/^$1=//p"; }

fail() { echo "netns: $*"; "$CTL" -r status; feed_all; exit 1; }

flood
sleep 0.5
STATUS=$("$CTL" -r status)
echo "during flood: $STATUS"
echo "$STATUS" | grep -q 'state=active' || {
    echo "expected active after flood"
    "$CTL" -r stats
    exit 1
}
[[ $(word attack "$STATUS") == 1 && $(word attack_id "$STATUS") == 1 ]] \
    || fail "expected attack 1 open"
(( $(word attack_tick_peak_pps "$STATUS") > 50 )) \
    || fail "expected the attack's peak over wake_pps"
feed_all | grep -q ' kind=attack source=self id=1 wake_rx_pps=[0-9]' \
    || fail "expected attack 1 in the feed"

"$CTL" block 198.51.100.1/32
"$CTL" blocks
flood
STATS=$("$CTL" -r stats)
echo "stats after block: $STATS"
echo "$STATS" | grep -E 'dropped=[1-9]' || {
    echo "expected dropped > 0"
    exit 1
}

# past the flood's last tick (idle_poll_ms), still inside clear_seconds:
# a disarm while the rate is still over wake_pps would start another
# attack at once, as proposal 0017 §1 has it
sleep 0.5
"$CTL" disarm
STATUS=$("$CTL" -r status)
echo "after disarm: $STATUS"
echo "$STATUS" | grep -q 'state=idle' || {
    echo "expected idle after disarm"
    exit 1
}

# the second flood kept attack 1 open; the disarm ended it, before its
# own entry, with what it cut and dropped
[[ $(word attack "$STATUS") == 0 && $(word last_attack_id "$STATUS") == 1 \
   && $(word last_attack_how "$STATUS") == disarm ]] \
    || fail "expected attack 1 ended by the disarm"
(( $(word last_attack_cut "$STATUS") >= 1 )) || fail "expected a cut"
(( $(word last_attack_dropped "$STATUS") > 0 )) || fail "expected drops"
feed_all | tail -2 | head -1 \
    | grep -q ' kind=attack-end source=socket uid=0 cause=disarm id=1 ' \
    || fail "expected attack 1's end just before the disarm"
feed_all | tail -1 | grep -q ' kind=disarm ' || fail "expected the disarm"

# from idle again: attack 2, which ends quiet clear_seconds after the
# flood, its end when the flood stopped; the policy block keeps the gate
# armed
flood
stopped=$(date +%s)
sleep 3.5
STATUS=$("$CTL" -r status)
echo "after quiet: $STATUS"
[[ $(word state "$STATUS") == active && $(word attack "$STATUS") == 0 \
   && $(word last_attack_id "$STATUS") == 2 \
   && $(word last_attack_how "$STATUS") == quiet ]] \
    || fail "expected attack 2 ended quiet, the gate armed"
end=$(word last_attack_end "$STATUS")
(( end >= (stopped - 1) * 1000 && end <= (stopped + 1) * 1000 )) \
    || fail "expected attack 2's end when the flood stopped ($stopped)"
feed_all | grep -q ' kind=attack-end source=self cause=quiet id=2 ' \
    || fail "expected attack 2's end in the feed"
echo "netns test passed"
