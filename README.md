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
         parse: only with sw_flowd     parse + LPM drop + counters
```

The wake thresholds compare received traffic less the replies to flows
the host opened itself (`rx_reply_pkts`, `rx_reply_bytes`), found in
sw_flowd's table, so the host's own downloads don't arm the gate (Seawall
proposal 0017 §1); idle, the data path parses each frame for that only
while the table is bound, and nothing without it.

## Requirements

- Linux 5.10+ with BTF (`/sys/kernel/btf/vmlinux`), and bpffs at
  `/sys/fs/bpf` (systemd mounts it)
- clang, llvm, libbpf and libxdp (both linked in statically: voidgate
  needs neither at run time), bpftool, libelf
- [sw_flowd](https://github.com/seawallnetworks/sw_flowd)'s header, the
  flow table voidgate reads: `make -C ../sw_flowd install-header` (or its
  `make install`) puts it in `/usr/local/seawall/include`;
  `SW_FLOWD_PREFIX` points elsewhere
- [libpkt](https://github.com/seawallnetworks/libpkt), the stack's packet
  parser: `make -C ../libpkt install` puts its headers in
  `/usr/local/seawall/include`; `LIBPKT_PREFIX` points elsewhere
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
sudo ./voidgatectl block 203.0.113.0/24
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

In the foreground, and so under the systemd service, voidgate logs to
stderr with libsw's `sw_log`: the journal, at each line's own priority
(`journalctl -u voidgate -p warning` finds its warnings), or a terminal.
With `-d` it has no stderr, and logs to `log_file` instead: omit the key
for `/var/log/voidgate.log`. That file is created with mode `0644`
subject to the process umask; parent directories must already exist.
`pid_file` is `/run/voidgate.pid` when omitted; `-s stop` reads it.
Relative log, pid, and config paths use the launch directory, which the
daemon retains for configuration reloads. `-v` adds debug lines, `-vv`
the per-source and idle-tick ones too. Restart voidgate after rotating
the log file or changing its destination; configuration reload does not
reopen logs or move the pid file.

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

## The read-only socket

Monitoring reads the gate without being able to change it (Seawall
proposal 0012 §2). `-R <group>` opens `/run/voidgate-monitor.sock`,
`0660 root:<group>`; the shipped unit runs `-R sw_monitor`. It answers
`status`, `stats`, `feed` and `blocks`, and every other
command with `error: read-only socket`. The control socket answers all
of them.

```sh
voidgatectl -s /run/voidgate-monitor.sock feed
```

- `feed` gives the cursor; `feed <epoch> <seq>` every entry after it,
  oldest first: blocks added and lifted, arm, disarm and reload, and
  attacks started and ended (below).

  ```
  epoch=9f2c41d07a6be3e1 seq=3 oldest=1 gap=0 n=2 more=0
  seq=2 time=1763150000123 kind=arm source=socket uid=0 cause=manual-block
  seq=3 time=1763150000123 kind=block source=socket uid=0 id=1 cidr=198.18.0.1/32 reason=manual expires=0
  ```

  `source=socket` is a command on the control socket, `source=ban` a
  block on the ban socket (below), both with the caller's uid
  (`SO_PEERCRED`); a change the command causes, such as the arm before
  a block on an idle gate (`cause=manual-block`, or `cause=ban`), is the
  caller's too; `unblock` lifts with `cause=unblock`. `source=self` is
  voidgate's own: the wake threshold, policy and aggregate blocks, timed
  lifts (`cause=expired`). `disarm` lifts every block, in one change. `more=1`: read
  again from the last seq.
- The epoch is drawn at each start; a reload keeps it. A cursor of
  another epoch, older than the last 8192 entries, or not reached yet,
  is a gap (`gap=1`, no entries): read the blocks back, and carry on from
  that reply's seq.
- **Attacks** (Seawall proposal 0017). One starts on the first tick when
  received traffic less the host's own replies (`wake_rx_pps`,
  `wake_rx_bps`) exceeds `wake_pps` or `wake_mbps`, whether the gate is
  idle (it arms first) or armed already. It ends when that traffic has
  stayed below both for `clear_seconds` (`how=quiet`, its `end` when
  traffic fell, to the second), before an automatic disarm on the same
  tick; or with a disarm, a command or shutdown (`how=disarm`, its `end`
  the disarm's time). A reload doesn't end it. One at a time, numbered
  from 1 after each start; a restart forgets an open one.

  ```
  seq=7 time=1763150000123 kind=attack source=self id=1 wake_rx_pps=25268 wake_rx_bps=21427032
  seq=12 time=1763150004378 kind=attack-end source=self cause=quiet id=1 start=1763150000123 end=1763150002000 how=quiet tick_peak_pps=27575 tick_peak_bps=23383708 dropped=83898 cut=1 bans=0
  ```

  `wake_rx_*`, the rates that started it; `tick_peak_*`, the highest
  tick's; `dropped`, every packet dropped while it was open, a permanent
  manual block's too; `cut`, the policy and aggregate blocks added;
  `bans`, the ban socket's. Times are Unix ms. `status` says `attack=1`
  with `attack_id`, `attack_since` and `attack_tick_peak_pps` and `_bps`
  so far, and keeps the last ended attack's record under `last_attack_`
  (`last_attack_id`, `_start`, `_end`, `_how`, `_tick_peak_pps`,
  `_tick_peak_bps`, `_dropped`, `_cut`, `_bans`) until the next one ends.
  `voidgatectl status`'s table shows `attack` alone; `-r status` has all.
- `blocks`, then `blocks after <next>` until `next=end`: every listed
  block, 256 a page, oldest first by id (ids only grow). `voidgatectl
  blocks` reads every page and prints one table; `voidgatectl -r blocks`
  prints the daemon's first page, as below.

  ```
  epoch=9f2c41d07a6be3e1 seq=3 n=1 next=end
  id=1 cidr=198.18.0.1/32 reason=manual inserted=1763150000 expires=0
  ```

## OpenResty integration

voidgate is not a WAF. Let OpenResty, or a gateway built on it such as Kong
or APISIX, decide which client is abusive (`limit_req`, failed logins, bot
rules) and push that address down to XDP with a timed block. The design and
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

nginx workers do not run as root. `M.ban()` and `M.ban_now()` talk to
the ban socket, `/run/voidgate-ban.sock` (Seawall proposal 0012 §2),
which the shipped unit opens with `-B voidgate_ban`: `0660
root:voidgate_ban`, the group from the seawall repo, which `make
install` needs first. It takes only `block <address> ttl=<seconds>`,
one address (`/32`, `/128` or bare, never a network), and refuses
everything else (`error: denied: ...`): a gateway or an application
server that faces the internet, if compromised, can block single
addresses for a while, and can't block a range, disarm the gate,
reload it or lift a block. Add the workers' user to the group and
restart the gateway:

```sh
sudo usermod -aG voidgate_ban kong
```

**Upgrading from a voidgate without the ban socket:** `M.ban()` and
`M.ban_now()` used `/run/voidgate.sock`, and the workers' user was told
to join `voidgate`. They now use the ban socket: until that user joins
`voidgate_ban`, every ban fails, with only a line in nginx's error log
(`voidgate: block ...: permission denied`). Add it to `voidgate_ban`,
restart the gateway, then take it out of `voidgate`
(`sudo gpasswd -d kong voidgate`) unless it also calls the other
methods, which need the control socket.

An application banning directly, not through a gateway, joins the same
group. Its changes are `source=ban` with its uid, so several ban
clients are told apart.

| Gateway | Common worker user, group | Set by |
| --- | --- | --- |
| OpenResty | `nobody`, `nogroup` (Debian/Ubuntu) or `nobody` (RHEL) | `user` in `nginx.conf` |
| Kong | `kong`, `kong` | `nginx_user` in `kong.conf` |
| APISIX | `nobody`; `apisix` in the official Docker image | `nginx_config.user` in `config.yaml` |

That table is for a master started as root, which drops the workers to the
`user` directive. A master started as an ordinary user (for example
`openresty -p ~/work` as `ubuntu`) ignores `user` and runs its workers as
itself: add that user. A worker user many services share, such as
`nobody`, would bring them all in: give the gateway a user of its own, or
pass the workers' group to `-B` instead (`systemctl edit voidgate`). `-B`
takes effect at start; reload keeps the socket's group.

Check the real group with `ps -eo user,group,args | grep 'worker process'`.
If the gateway runs in a container with the socket bind-mounted, the
container's worker must have the same numeric gid as the group on the host.
A group missing from `/etc/group`, or a failed chown, stops the start
before voidgate touches the NIC.

The client's methods (`status`, `disarm`, `block` and the rest, through
`M.new()`) use the control socket, `/run/voidgate.sock`, `0660
root:voidgate` (`-g voidgate`). Its members get the whole protocol,
`disarm` and `reload` included: as good as root over voidgate. Join
`voidgate` only a program that really needs that.

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
use ban()"`. Every block from Lua has a ttl; a permanent block is an
operator's decision (`voidgatectl block <cidr>`).

The ban is `block <ip> ttl=<ttl>` on the socket (`reason=timed`). It lifts
itself after `ttl` seconds (1 to one year). Banning the same prefix again
only extends it, a manual `block` of it makes it permanent, and timed
blocks never count toward `aggregate_k`, so a few bans behind one NAT do
not become a `/24` block. Like every block, a ban arms the gate until it
lifts, and
`disarm` or a daemon restart forgets it.

Ban only real peers. Behind a CDN or load balancer, take the client address
from the proxy header only for trusted proxies (`set_real_ip_from`), and put
the proxy ranges in `allow_networks`. Otherwise a forged header bans your
own front door. The daemon refuses blocks that cover `allow_networks` or
`local_networks`.

### Methods

```lua
local vg = require("resty.voidgate")

local status = assert(vg.status())
ngx.say(status.state, " ", status.rx_pps)

local ok, err = vg.ban_now("203.0.113.7", 600)  -- 10m; the daemon's answer

assert(vg.block("203.0.113.0/24", 600))          -- 10m; a prefix, ttl required
assert(vg.unblock("203.0.113.0/24"))

for _, b in ipairs(assert(vg.blocks())) do       -- every block, oldest first
    ngx.say(b.cidr, " ", b.reason, " ", b.expires)
end

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
| `status()` | Table: `state`, boolean `armed`, numeric `rx_pps`, `rx_bps`, `blocked`, string `iface` |
| `stats()` | Table: the counters, as decimal strings; the rates, `blocked` and `state` are `status()`'s |
| `blocks()` | Array of `{ id, cidr, reason, inserted, expires }`, oldest first, every page read; empty when nothing is blocked |
| `arm()`, `disarm()`, `reload()` | `true` |
| `block(cidr, ttl)`, `unblock(cidr)` | `true`; `ttl` (seconds, 1–31536000) is required, and the daemon lifts the block itself |
| `ban(ip, ttl [, opt])` | `true` once queued; see above |
| `ban_now(ip, ttl [, opt])` | `true`, or `nil, err` with the daemon's answer |

Operations return `nil, error` on connection, timeout, or daemon errors.
CIDR validity is checked by the daemon; the client only rejects a CIDR
that contains whitespace. `stats()` keeps `rx_pkts`, `rx_bytes`, `passed`,
`dropped`, `non_ip`, `map_full`, `parse_err`, `reply_passed`,
`rx_reply_pkts` and `rx_reply_bytes` as strings
to avoid precision loss. A block's `reason` is `manual`, `policy`, `aggregate` or
`timed`; `id`, `inserted` and `expires` (Unix seconds) are numbers.
`expires` is a timed block's lift time, else 0: a manual block never
expires, a policy or aggregate one `ban_time` after `inserted`. The default timeout is one second per socket operation.

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
- When the flood, less the host's own replies, is gone for
  `clear_seconds` and the drop tree is empty,
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
