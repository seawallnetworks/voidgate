#!/bin/bash
# Integration: veth pair, daemon starts IDLE, flood wakes it, drop works.
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
STATUS=$("$CTL" status || true)
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

flood
sleep 0.5
STATUS=$("$CTL" status)
echo "during flood: $STATUS"
echo "$STATUS" | grep -q 'state=active' || {
    echo "expected active after flood"
    "$CTL" stats
    exit 1
}

"$CTL" drop 198.51.100.1/32
"$CTL" drops
flood
STATS=$("$CTL" stats)
echo "stats after drop: $STATS"
echo "$STATS" | grep -E 'dropped=[1-9]' || {
    echo "expected dropped > 0"
    exit 1
}

"$CTL" disarm
STATUS=$("$CTL" status)
echo "after disarm: $STATUS"
echo "$STATUS" | grep -q 'state=idle' || {
    echo "expected idle after disarm"
    exit 1
}
echo "netns test passed"
