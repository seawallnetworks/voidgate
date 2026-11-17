#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Run lua/resty/voidgate.lua inside nginx against a daemon in private
# namespaces: the client methods (resty.lua) and ban(). Needs OpenResty, or
# nginx with lua-nginx-module (Ubuntu: libnginx-mod-http-lua); set NGINX
# to pick the binary. Workers run as nobody:nogroup, so this also covers
# -g.
set -euo pipefail

. "$(dirname "$0")/../bin/create_env.sh"

conf=$work/voidgate.conf
prefix=$work/nginx

nginx=${NGINX:-$(command -v openresty || command -v nginx || true)}
if [[ -z $nginx ]]; then
    echo "skip: no openresty or nginx in PATH (set NGINX)" >&2
    exit 0
fi

# refute <cmd...>: fail if cmd succeeds. Not "! cmd": set -e ignores a
# negated command, so "! grep ..." can never fail the script.
refute() {
    if "$@"; then
        echo "${0##*/}: unexpectedly true: $*" >&2
        return 1
    fi
}

cleanup() {
    local result=$?
    trap - EXIT
    if [[ $result != 0 && -e $prefix/error.log ]]; then
        cat "$prefix/error.log" >&2
    fi
    if [[ -e $prefix/nginx.pid ]]; then
        "$nginx" -p "$prefix" -c nginx.conf -s stop 2>/dev/null || true
    fi
    if [[ -e $work/voidgate.pid ]]; then
        "$root/voidgate" -s stop -c "$conf" 2>/dev/null || true
    fi
    exit "$result"
}
trap cleanup EXIT

cp "$root/t/conf/idle.conf" "$conf"
printf 'log_file = %s\n' "$work/daemon.log" >> "$conf"
printf 'pid_file = %s\n' "$work/voidgate.pid" >> "$conf"
# -v: one log line per block, so the dedup check below can count them.
# -B: ban() and ban_now() use the ban socket.
timeout --kill-after=2 10 "$root/voidgate" -d -v -g nogroup -B nogroup -c "$conf"

modules=
for m in ndk_http_module ngx_http_lua_module; do
    if [[ -e /usr/lib/nginx/modules/$m.so ]]; then
        modules+="load_module /usr/lib/nginx/modules/$m.so;"$'\n'
    fi
done

# Workers (nobody) may not read the checkout under a home directory.
mkdir -p "$prefix"
cp -r "$root/lua" "$work/lua"
cp "$root/t/integration/resty.lua" "$work/resty.lua"
chmod -R a+rX "$work"
chmod a+w "$conf"     # resty.lua rewrites it to test reload
cat > "$prefix/nginx.conf" <<NGINX
$modules
user nobody nogroup;
worker_processes 2;
pid $prefix/nginx.pid;
error_log $prefix/error.log info;
events {}
http {
    access_log off;
    lua_package_path "$work/lua/?.lua;;";
    lua_shared_dict vg_ban 1m;

    server {
        listen 127.0.0.1:8080;
        default_type text/plain;

        location = /t {
            set \$vg_conf $conf;
            content_by_lua_file $work/resty.lua;
        }

        location = /blocks {
            content_by_lua_block {
                for _, b in ipairs(assert(require("resty.voidgate").blocks())) do
                    ngx.say(b.cidr, " ", b.reason)
                end
            }
        }

        # ban_now() in the log phase: no cosocket there, so an error
        # return (not a raised error that aborts the handler).
        location = /ban_now_log {
            content_by_lua_block { ngx.say("ok") }
            log_by_lua_block {
                local ok, err = require("resty.voidgate").ban_now(
                    ngx.var.arg_ip, 60)
                ngx.log(ngx.ERR, "ban_now from log: ", tostring(ok), " ", err)
            }
        }

        # ban() from the log phase, where cosockets are not allowed.
        location = /ban {
            content_by_lua_block { ngx.say("queued") }
            log_by_lua_block {
                local ok, err = require("resty.voidgate").ban(
                    ngx.var.arg_ip, 60, { dict = "vg_ban" })
                if not ok then
                    ngx.log(ngx.ERR, "ban: ", err)
                end
            }
        }
    }
}
NGINX

"$nginx" -p "$prefix" -c nginx.conf

get() {
    curl -fsS --retry 5 --retry-connrefused --retry-delay 0 \
        "http://127.0.0.1:8080$1"
}

wait_blocks() {
    local i
    for i in $(seq 50); do
        [[ $(get /blocks) == "$1" ]] && return 0
        sleep 0.1
    done
    echo "blocks: want '$1', got '$(get /blocks)'" >&2
    return 1
}

tap=$(get /t)
echo "$tap"
[[ $tap != *'not ok'* && $tap == *$'\n'1..* ]]

# Fifty requests from one address: one ban sent (shared-dict window).
for i in $(seq 50); do
    get '/ban?ip=198.18.0.20' > /dev/null
done
get '/ban?ip=2001:db8::20' > /dev/null
wait_blocks $'198.18.0.20/32 timed\n2001:db8::20/128 timed'
[[ $(grep -c 'block 198.18.0.20/32 (timed)' "$work/daemon.log") == 1 ]]
# The per-tick summary lands on the next tick (idle_poll_ms).
for i in $(seq 30); do
    grep -q '\] blocked .*198.18.0.20/32 (timed)' "$work/daemon.log" && break
    sleep 0.1
done
grep -q '\] blocked .*198.18.0.20/32 (timed)' "$work/daemon.log"
get '/ban?ip=1.2.3.4/24' > /dev/null
get '/ban_now_log?ip=198.18.0.30' > /dev/null
sleep 0.2
grep -q 'ban: bad ip' "$prefix/error.log"
grep -q 'ban_now from log: nil no cosocket in this phase, use ban()' \
    "$prefix/error.log"
refute grep -q 'failed to run log_by_lua' "$prefix/error.log"
blocks=$("$root/voidgatectl" -r blocks)
refute grep -q '198.18.0.30/32' <<< "$blocks"
# The "missing socket" check in resty.lua makes nginx's core log a [crit]
# connect() failure; anything else at crit or alert is a bug.
grep '\[alert\]\|\[crit\]' "$prefix/error.log" \
    | grep -v 'connect() to unix:/run/voidgate.sock.missing failed' \
    > "$work/unexpected.log" || true
[[ ! -s $work/unexpected.log ]] || { cat "$work/unexpected.log" >&2; exit 1; }

echo "resty client tests passed"
