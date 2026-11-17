#!/usr/bin/env bash
# voidgatectl's stats tables against a fake voidgate: no root, no NIC.
# Usage: t/unit/voidgatectl.sh [voidgatectl]
set -euo pipefail

ctl=$(realpath "${1:-./voidgatectl}")
work=$(mktemp -d)
server=

cleanup() {
    [[ -n $server ]] && kill "$server" 2> /dev/null
    rm -rf -- "$work"
}
trap cleanup EXIT

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

# answer a command with $work/<its first word>, split by "--" lines: the
# next part on each connection, the last one again and again; a command
# with no file is unknown. Each serve starts the counts over.
serve() {
    [[ -n $server ]] && kill "$server" 2> /dev/null && wait "$server" || true
    rm -f "$work/sock"
    python3 -I - "$work/sock" "$work" <<'PY' &
import os, socket, sys
path, work = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_UNIX)
s.bind(path)
s.listen(8)
n = {}
while True:
    c, _ = s.accept()
    word = c.recv(256).decode().split()[0]
    f = os.path.join(work, word)
    if os.path.exists(f):
        parts = open(f).read().split("--\n")
        out = parts[min(n.get(word, 0), len(parts) - 1)]
        n[word] = n.get(word, 0) + 1
    else:
        out = "error: unknown command\n"
    c.sendall(out.encode())
    c.close()
PY
    server=$!
    for _ in $(seq 50); do
        [[ -S $work/sock ]] && return
        sleep 0.1
    done
    fail "fake voidgate did not start"
}

# the time a row starts with, which the test can't know
untime() {
    sed -E 's/^[0-2][0-9]:[0-5][0-9]:[0-6][0-9]  /HH:MM:SS  /'
}

check() {
    local name=$1 want=$2 got=$3
    [[ $got == "$want" ]] || {
        diff <(printf '%s\n' "$want") <(printf '%s\n' "$got") >&2 || true
        fail "$name"
    }
}

# one reading, from status and stats, after the time: big counters in
# units, map_full and parse_err after the row, not 0 (non_ip and
# reply_passed only in -r), status's CRITICAL line first
cat > "$work/status" <<'A'
CRITICAL: no flow table: replies are judged as any other; start sw_flowd
state=active armed=1 rx_pps=552113 rx_bps=264900000 blocked=3 degraded=0 iface=eth0 hook=xdp-native flows=none
A
cat > "$work/stats" <<'A'
rx_pkts=5145645497 rx_bytes=308739129989 passed=3984474 dropped=5141661023 non_ip=4875 map_full=3 parse_err=12 reply_passed=2
A
serve

check once "$(cat <<'W'
CRITICAL: no flow table: replies are judged as any other; start sw_flowd

           state  blocked  rx_pkts  rx_pps  rx_bytes  rx_bps  passed  dropped   drop%
HH:MM:SS  active        3    5.15G    552k      309G    265M   3.98M    5.14G   99.92  map_full=3  parse_err=12
W
)" "$("$ctl" -s "$work/sock" stats | untime)"

# -r: the answer as is
check raw "$(cat "$work/stats")" "$("$ctl" -r -s "$work/sock" stats)"

# status: a column a key, in the daemon's order, no rates (stats has
# them); CRITICAL first
check status "$(cat <<'W'
CRITICAL: no flow table: replies are judged as any other; start sw_flowd

 state  armed  blocked  degraded  iface        hook  flows
active      1        3         0   eth0  xdp-native   none
W
)" "$("$ctl" -s "$work/sock" status)"
check "raw status" "$(cat "$work/status")" "$("$ctl" -r -s "$work/sock" status)"

# a key status doesn't give, from a voidgate of another version: "-",
# not 0
printf 'state=idle armed=0 rx_pps=6 prefixes=1 flows=sw_flowd\n' \
    > "$work/status"
serve
check unknown "$(cat <<'W'
           state  blocked  rx_pkts  rx_pps  rx_bytes  rx_bps  passed  dropped   drop%
HH:MM:SS    idle        -    5.15G       6      309G       -   3.98M    5.14G   99.92  map_full=3  parse_err=12
W
)" "$("$ctl" -s "$work/sock" stats | head -2 | untime)"

# an interval: stats's columns, the totals at the end of it, the rates,
# drop%, map_full and parse_err over it (5 map_full from before it, none);
# a restart starts over, and is one of the count rows
cat > "$work/status" <<'A'
state=idle armed=0 rx_pps=0 rx_bps=0 blocked=0 flows=sw_flowd
--
state=active armed=1 rx_pps=0 rx_bps=0 blocked=1 flows=sw_flowd
--
state=idle armed=0 rx_pps=0 rx_bps=0 blocked=0 flows=sw_flowd
A
cat > "$work/stats" <<'A'
rx_pkts=1000 rx_bytes=64000 passed=0 dropped=0 non_ip=0 map_full=0 parse_err=0 reply_passed=0
--
rx_pkts=501000 rx_bytes=32064000 passed=100 dropped=499900 non_ip=0 map_full=2 parse_err=0 reply_passed=0
--
rx_pkts=10 rx_bytes=640 passed=0 dropped=0 non_ip=0 map_full=5 parse_err=0 reply_passed=0
A
serve

out=$("$ctl" -s "$work/sock" stats 1 3)
head=$(sed -n 1p <<< "$out")
row=$(sed -n 2p <<< "$out" | cut -c11-)
reset=$(sed -n 3p <<< "$out" | cut -c11-)
row2=$(sed -n 4p <<< "$out" | cut -c11-)
check header "           state  blocked  rx_pkts  rx_pps  rx_bytes  rx_bps  passed  dropped   drop%" "$head"
# 500k packets in about a second: a busy host makes it a little longer
pps='(4[0-9]{2}k|50[0-9]k)'
[[ $row =~ ^\ *active\ +1\ +501k\ +$pps\ +32\.1M\ +2[0-9]{2}M\ +100\ +500k\ +99\.98\ +map_full=2$ ]] \
    || fail "interval row: $row"
check restart "voidgate restarted, counters reset" "$reset"
[[ $row2 =~ ^\ *idle\ +0\ +10\ +0\ +640\ +0\ +0\ +0\ +0\.00$ ]] \
    || fail "after restart: $row2"
[[ $(sed -n 5p <<< "$out") =~ ^Average:\ +-\ +-\ +-\ +0\ +-\ +0\ +-\ +-\ +0\.00$ ]] \
    || fail "average: $out"
(( $(wc -l <<< "$out") == 5 )) || fail "rows: $out"

# Ctrl-C: no Average row, exit 0
"$ctl" -s "$work/sock" stats 1 > "$work/out" &
pid=$!
sleep 2.5
kill -INT "$pid"
wait "$pid" || fail "Ctrl-C exit $?"
! grep -q '^Average:' "$work/out" || fail "Average on Ctrl-C"
grep -q '^[0-9][0-9]:' "$work/out" || fail "no rows before Ctrl-C"

# blocks: every page, as one table, in local time; a policy or aggregate
# block lifts ban_time after since, which the daemon doesn't say
cat > "$work/blocks" <<'A'
epoch=00000000000000aa seq=5 n=2 next=2
id=1 cidr=198.18.0.1/32 reason=manual inserted=1763150000 expires=0
id=2 cidr=2001:db8::4/128 reason=timed inserted=1763150000 expires=1763150600
--
epoch=00000000000000aa seq=5 n=1 next=end
id=17 cidr=203.0.113.0/24 reason=aggregate inserted=1763150060 expires=0
A
serve

check blocks "$(cat <<'W'
id  cidr             reason     since                expires
 1  198.18.0.1/32    manual     2025-11-14 19:53:20  never
 2  2001:db8::4/128  timed      2025-11-14 19:53:20  2025-11-14 20:03:20
17  203.0.113.0/24   aggregate  2025-11-14 19:54:20  ban_time
W
)" "$(TZ=UTC "$ctl" -s "$work/sock" blocks)"

# a voidgate restarted between the pages: its ids start over
cat > "$work/blocks" <<'A'
epoch=00000000000000aa seq=5 n=1 next=1
id=1 cidr=198.18.0.1/32 reason=manual inserted=1763150000 expires=0
--
epoch=00000000000000bb seq=0 n=0 next=end
A
serve
if "$ctl" -s "$work/sock" blocks > /dev/null 2> "$work/err"; then
    fail "blocks across a restart"
fi
grep -q 'voidgate restarted' "$work/err" || fail "restart: $(cat "$work/err")"

# a next not past the last id would never end
printf 'epoch=00000000000000aa seq=5 n=0 next=0\n' > "$work/blocks"
serve
if "$ctl" -s "$work/sock" blocks 2> /dev/null; then fail "next=0"; fi

printf 'epoch=00000000000000aa seq=5 n=0 next=end\n' > "$work/blocks"
serve
check "no blocks" "(none)" "$("$ctl" -s "$work/sock" blocks)"
check "raw blocks" "$(cat "$work/blocks")" \
    "$("$ctl" -r -s "$work/sock" blocks)"

# a refused command fails
printf 'error: read-only socket\n' > "$work/status"
serve
if "$ctl" -s "$work/sock" stats 2> /dev/null; then fail "error answer"; fi
if "$ctl" -s "$work/sock" stats 0 2> /dev/null; then fail "interval 0"; fi
if "$ctl" -s "$work/sock" stats 1 x 2> /dev/null; then fail "count x"; fi

echo "voidgatectl: ok"
