# voidgate

Multi-layer XDP shield for a single Linux VM. Silent unless the instance
is under attack.

Website: [https://voidgate.co/](https://voidgate.co/).
Source is [`docs/`](docs/). Enable once in the GitHub UI: Settings → Pages →
Deploy from a branch → `main` / `/docs`.

Watch the NIC idle, keep the VM reachable, cut attacker hosts, then
widen to `/24` or `/64` when the cluster is dense. There is no NetFlow,
sFlow, AF_PACKET, or AF_XDP. Packets are not redirected to userspace.
The XDP program either `XDP_PASS` or `XDP_DROP`. Userspace is the
control plane: it watches coarse rx rates, and only when the NIC is
flooded does it arm the gate, count sources, and install CIDRs into a
BPF LPM drop tree.

```
IDLE  ── wake_pps / wake_mbps ──► ACTIVE ── quiet clear_seconds ──► IDLE
         cfg.armed = 0                 cfg.armed = 1
         parse: no                     parse + LPM drop + counters
```

## Requirements

- Linux 5.10+ with BTF (`/sys/kernel/btf/vmlinux`), and bpffs at
  `/sys/fs/bpf` (systemd mounts it)
- clang, llvm, libbpf and libxdp (both linked in statically: voidgate
  needs neither at run time), bpftool, libelf
- [sw_flowd](https://github.com/seawallnetworks/sw_flowd)'s header, the
  flow table voidgate reads: `make -C ../sw_flowd install-header` (or its
  `make install`) puts it in `/usr/local/seawall/include`;
  `SW_FLOWD_PREFIX` points elsewhere
- `CAP_BPF`, `CAP_NET_ADMIN` and `CAP_SYS_ADMIN`, which libxdp needs to
  read the hook's programs and use its dispatcher (root is fine)

On Ubuntu 24.04:

```
sudo apt install clang llvm libbpf-dev libxdp-dev libelf-dev zlib1g-dev \
    linux-tools-generic make gcc libtest-base-perl
make
make test
sudo make install
sudo systemctl enable --now voidgate
```

On Amazon Linux 2023 (and RHEL 9), the same with dnf; the Perl tests
also need Test::Base (`cpan Test::Base`):

```
sudo dnf install clang llvm libbpf-devel libbpf-static libxdp-devel libxdp-static \
    elfutils-libelf-devel zlib-devel bpftool make gcc
```

`make install` installs into the
[Seawall](https://github.com/seawallnetworks/seawall) stack's prefix,
`/usr/local/seawall`: `sbin/voidgate`, `bin/voidgatectl`, the default
config in `share/voidgate/voidgate.conf`, `libexec/voidgate-mkconf`,
the unit in `/etc/systemd/system`, and the OpenResty client in the
stack's OpenResty (below). `PREFIX`, `CONFDIR`, `LUA_DIR` and
`DESTDIR` change the locations; the unit runs
`/usr/local/seawall/sbin/voidgate` whatever `PREFIX` is.

The config is `/usr/local/seawall/etc/voidgate/voidgate.conf` (`-c`
changes it). On its first start the unit makes it from the default,
with `interface` set to the one the default route goes out of, and
never changes it after that: edit it there, and `make install` and
upgrades keep it. `make uninstall` keeps it too.

## Run

```
sudo ./voidgate -c configs/voidgate.conf -i eth0
sudo ./voidgatectl status
sudo ./voidgatectl drop 203.0.113.0/24
sudo ./voidgatectl disarm
```

Prometheus: `http://127.0.0.1:9105/metrics`

Use `-d` to detach and run in the background:

```sh
sudo ./voidgate -d -c configs/voidgate.conf
sudo ./voidgate -s stop
```

The command waits for startup before returning success and printing the daemon
PID to stderr. Startup failures return nonzero; after detachment, diagnostic
details are in the log file. SIGTERM shuts down the daemon and detaches XDP.
The supplied systemd service continues running in the foreground.

`log_file` in the configuration selects the append-only log. Omit the key for
`/var/log/voidgate.log`. Files are created with mode `0644` subject to
the process umask; parent directories must already exist. `pid_file` is
`/run/voidgate.pid` when omitted; `-s stop` reads it. Relative log, pid, and
config paths use the launch directory, which the daemon retains for
configuration reloads. `-v` and `-vv` retain their usual verbosity. Restart
voidgate after rotating the log file or changing its destination; configuration
reload does not reopen logs or move the pid file.

Only one daemon runs at a time. It holds a lock on the pid file for its whole
life, and a second `voidgate` exits with `already running (pid N, <pid_file>)`
before touching the NIC or the control socket. A second instance with a
different `pid_file` is refused too while another daemon answers on
`/run/voidgate.sock`. After a crash the lock is released by the kernel, so a
restart takes over the leftover socket, and takes the dead daemon's
program off the NIC. `-s stop` refuses a
pid file that no running daemon holds (`is stale: voidgate is not running`),
removes it, and never signals the pid inside.

Run `sudo t/integration/daemon.sh` to test daemon startup and logging in
isolated mount, network and PID namespaces (requires sudo and BPF support).

Edit `interface` in the config to the VM's public NIC. Do not point this
at a shared management-only interface you cannot afford to XDP-attach;
the idle path is `XDP_PASS`, but attach still requires driver/SKB XDP.

## Sharing the XDP hook

An interface has one XDP hook. voidgate attaches with
[libxdp](https://github.com/xdp-project/xdp-tools), whose dispatcher runs
several programs in turn: voidgate's at priority 10, first, then
[mini-fw](https://github.com/seawallnetworks/mini-fw)'s and the
operator's own libxdp programs. What voidgate drops goes no further.

voidgate never replaces a program it did not attach. When one that is
not a dispatcher holds the hook (attached with `ip link`, or a `bpf_link`
such as Cilium's), voidgate judges at TC ingress instead: with tcx,
first, on Linux 6.6 and later; before, with a `cls_bpf` filter on the
`clsact` qdisc, at priority 0x100. The verdicts are the same, but a TC
drop costs more, after the kernel has built an skb: voidgate logs it as
degraded, and `voidgatectl status` says `degraded=1`, with `hook=tcx`
or `hook=tc` (`xdp-native` or `xdp-skb` at XDP). `hook = xdp` in the
config fails instead, `hook = tc` always takes TC.

## OpenResty integration

voidgate is not a WAF. Let OpenResty, or a gateway built on it such as Kong
or APISIX, decide which client is abusive (`limit_req`, failed logins, bot
rules) and push that address down to XDP with a timed drop. The design and
its trade-offs are in [`doc/l7-bridge.md`](doc/l7-bridge.md).

A complete OpenResty config is in
[`contrib/openresty/nginx.conf`](contrib/openresty/nginx.conf): the shared
dict, a honeypot path banned with `ban_now()` in the access phase,
`limit_req` 429s banned with `ban()` in the log phase, a health timer, and
a local status page.

`lua/resty/voidgate.lua` is a non-blocking client. It talks to the daemon's
Unix socket with an `ngx.socket.tcp` cosocket and needs no other library.
`make install` puts it in the stack's OpenResty's lualib.
`make install-lua` installs only the client, and `LUA_DIR` points it at
your gateway's Lua path (Kong: `lua_package_path` in `kong.conf`; APISIX:
`apisix.extra_lua_path` in `config.yaml`):

```sh
sudo make install-lua                     # /usr/local/seawall/openresty/site/lualib
sudo make install-lua LUA_DIR=/opt/lualib
```

nginx workers do not run as root. The shipped unit runs `voidgate -g
voidgate`, so `/run/voidgate.sock` is `0660 root:voidgate`; the group
comes from the seawall repo, which `make install` needs first. Add the
workers' user to it and restart the gateway:

```sh
sudo usermod -aG voidgate kong
```

| Gateway | Common worker user, group | Set by |
| --- | --- | --- |
| OpenResty | `nobody`, `nogroup` (Debian/Ubuntu) or `nobody` (RHEL) | `user` in `nginx.conf` |
| Kong | `kong`, `kong` | `nginx_user` in `kong.conf` |
| APISIX | `nobody`; `apisix` in the official Docker image | `nginx_config.user` in `config.yaml` |

That table is for a master started as root, which drops the workers to the
`user` directive. A master started as an ordinary user (for example
`openresty -p ~/work` as `ubuntu`) ignores `user` and runs its workers as
itself: add that user. Members get the whole protocol, disarm and reload
included. A worker user many services share, such as `nobody`, would
bring them all in: give the gateway a user of its own, or pass the
workers' group to `-g` instead (`systemctl edit voidgate`). `-g` takes
effect at start; reload keeps the socket's group.

Check the real group with `ps -eo user,group,args | grep 'worker process'`.
If the gateway runs in a container with the socket bind-mounted, the
container's worker must have the same numeric gid as the group on the host.
Members of that group get the whole protocol, `disarm` and `reload`
included. An unknown group only logs a warning and leaves the socket
root-only.

### Banning from a request

```nginx
lua_shared_dict voidgate_ban 1m;

location / {
    limit_req zone=api burst=20 nodelay;
    limit_req_status 429;
    log_by_lua_block {
        if ngx.status == 429 then
            require("resty.voidgate").ban(ngx.var.remote_addr, 600,  -- 10m
                                          { dict = "voidgate_ban" })
        end
    }
}
```

`ban(ip, ttl, opt)` works from every phase but `init_by_lua*`, log included:
it queues the request in an `ngx.timer.at` timer and returns `true`. The
daemon's answer goes to the nginx error log. With `opt.dict`, an address is
sent at most once per `opt.window` seconds (default 10), so the burst before
XDP takes over does not queue one timer per request. `opt.client` takes a
client from `new()`. A Kong or APISIX plugin calls the same function from
its `log` handler.

When the caller needs the daemon's answer, for example in `access_by_lua*`
or a timer, use `ban_now(ip, ttl)`: the same rules, sent at once, returning
`true` or `nil, err` (a refused address, a daemon that is down). It needs a
cosocket, so in the log phase it returns `nil, "no cosocket in this phase,
use ban()"`. Every drop from Lua has a ttl; a permanent drop is an
operator's decision (`voidgatectl drop <cidr>`).

The ban is `drop <ip> ttl=<ttl>` on the socket (`reason=4`). It lifts itself
after `ttl` seconds (1 to one year). Banning the same prefix again only
extends it, a manual `drop` of it makes it permanent, and timed drops never
count toward `aggregate_k`, so a few bans behind one NAT do not become a
`/24` drop. Like every drop, a ban arms the gate until it lifts, and
`disarm` or a daemon restart forgets it.

Ban only real peers. Behind a CDN or load balancer, take the client address
from the proxy header only for trusted proxies (`set_real_ip_from`), and put
the proxy ranges in `allow_networks`. Otherwise a forged header bans your
own front door. The daemon refuses drops that cover `allow_networks` or
`local_networks`.

### Methods

```lua
local vg = require("resty.voidgate")

local status = assert(vg.status())
ngx.say(status.state, " ", status.rx_pps)

local ok, err = vg.ban_now("203.0.113.7", 600)  -- 10m; the daemon's answer

assert(vg.drop("203.0.113.0/24", 600))           -- 10m; a prefix, ttl required
assert(vg.undrop("203.0.113.0/24"))

-- Optional settings; each call opens and closes its own connection.
local client = vg.new({ path = "/run/voidgate.sock", timeout = 1 })
local stats = assert(client:stats())
ngx.say(stats.rx_pkts) -- Decimal string: preserves all 64 bits.
```

Cosockets yield, so call the methods and `ban_now()` from `rewrite`,
`access`, `content` or a timer; elsewhere they return `nil, err`. Use
`ban()` from the other phases; neither works in `init_by_lua*`.
The full table is in `doc/l7-bridge.md` §9.

| Method | Successful return |
| --- | --- |
| `status()` | Table: `state`, boolean `armed`, numeric `rx_pps`, `rx_bps`, `prefixes`, string `iface` |
| `stats()` | Table: counters as decimal strings; numeric rates and prefix count; string `state` |
| `drops()` | Array of `{ cidr, reason, age }` entries; empty array when there are no drops |
| `arm()`, `disarm()`, `reload()` | `true` |
| `drop(cidr, ttl)`, `undrop(cidr)` | `true`; `ttl` (seconds, 1–31536000) is required, and the daemon lifts the drop itself |
| `ban(ip, ttl [, opt])` | `true` once queued; see above |
| `ban_now(ip, ttl [, opt])` | `true`, or `nil, err` with the daemon's answer |

Operations return `nil, error` on connection, timeout, or daemon errors.
CIDR validity is checked by the daemon; the client only rejects a CIDR
that contains whitespace. `stats()` keeps `rx_pkts`, `rx_bytes`, `passed`,
`dropped`, `non_ip`, `map_full`, and `parse_err` as strings to avoid
precision loss. Drop `reason` and `age` (seconds) are numbers. The
default timeout is one second per socket operation. The daemon has an
8192-byte response buffer, so large `drops()` lists may be truncated.

The protocol is one newline-terminated command per connection, followed by a
text response and connection close. Commands are limited to 254 bytes before
the newline. The server also accepts a command terminated by a write-side EOF.
`voidgatectl` exits 1 when the daemon answers `error: ...`.

Run the client tests against an isolated real daemon (requires sudo, BPF
support, curl, and OpenResty or nginx with `lua-nginx-module`; on Ubuntu,
`nginx-core` and `libnginx-mod-http-lua`):

```sh
sudo t/integration/resty.sh
```

`resty.sh` runs nginx in private namespaces with workers as
`nobody:nogroup`, the method tests in `t/integration/resty.lua`, and `ban()`
from the log phase. It skips when neither `openresty` nor `nginx` is in
`PATH`; set `NGINX` to choose the binary.

## How it decides

- **IDLE**: XDP increments `rx_pkts` / `rx_bytes` and passes. Userspace
  polls those counters. No drop tree, no per-source maps written.
- **ACTIVE**: XDP parses IPv4/IPv6, hard-passes NDP/SSH/DHCP, drops
  prefixes in `drop_v4`/`drop_v6`, counts local hosts and remote sources.
- Control plane inserts attacker `/32`/`/128` (and aggregates to
  `/24`/`/64` when dense). It will not install a prefix that covers the
  VM itself or the allow list.
- When the flood is gone for `clear_seconds` and the drop tree is empty,
  it disarms. Remote LRU maps are **not** wiped (no cheap BPF clear);
  rates are re-baselined on the next arm.

## Layout

```
src/bpf/voidgate.bpf.c   data plane: XDP and TC entries
src/bpf/voidgate.h       shared map/packet structs
src/voidgate.c           daemon
src/voidgatectl.c        voidgatectl
lua/resty/voidgate.lua   OpenResty control client
contrib/openresty/       example OpenResty config
src/policy.c             IDLE/ACTIVE policy
src/maps.c               attach (libxdp, or TC) + LPM helpers
```
