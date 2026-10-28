# voidgate operations and maintenance

voidgate is an XDP DDoS shield for one Linux VM: it passes everything
until the NIC floods, then drops attacker prefixes in the kernel. This
manual is for the operator who installs, configures, watches and upgrades
it on a host in the Seawall stack.

Contents:

1. [Overview](#1-overview)
2. [Building and installing](#2-building-and-installing)
3. [Configuration](#3-configuration)
4. [Running the service](#4-running-the-service)
5. [Control socket and day-to-day operations](#5-control-socket-and-day-to-day-operations)
6. [Logging and the OpenResty bridge](#6-logging-and-the-openresty-bridge)
7. [Maintenance](#7-maintenance)
8. [Troubleshooting](#8-troubleshooting)
9. [Reference](#9-reference)

## 1. Overview

The data plane is one BPF program that only ever returns `XDP_PASS` or
`XDP_DROP`; no packet goes to userspace. The daemon is the control plane:
it polls coarse rx counters and, when a wake threshold trips, arms the
gate, counts sources and installs CIDRs into an LPM drop tree.

| State | Data plane does | Leaves when |
| --- | --- | --- |
| IDLE (`armed=0`) | Counts `rx_pkts` / `rx_bytes`, passes everything | rx exceeds `wake_pps` or `wake_mbps` |
| ACTIVE (`armed=1`) | Parses IPv4/IPv6, drops prefixes in the drop trees, passes replies to the host's own flows, counts sources | rx below both wake thresholds for `clear_seconds` and the drop tree is empty |

An armed gate passes replies to flows the host opened itself (a download,
an update, a DNS query) and never counts them against their source, so a
fast download cannot get its server banned. It reads them from
[sw_flowd](https://github.com/seawallnetworks/sw_flowd)'s table, which
records the host's outbound flows at TC egress (Seawall proposals 0007
and 0009). voidgate binds that table when it starts, so sw_flowd starts
first (the unit is `After=` and `Wants=sw_flowd.service`). Started
without it, voidgate judges those replies as any other until it is
restarted; restarting sw_flowd needs no restart of voidgate, `sw_flowd
-P` does.
No drop stops such a flow, a manual one included: a drop keeps out
traffic the host did not ask for, not the replies it did.

Components:

| Component | Installed as | Role |
| --- | --- | --- |
| `voidgate` | `/usr/local/seawall/sbin/voidgate` | Daemon: loads BPF, attaches, runs policy, serves the control socket and metrics |
| `voidgatectl` | `/usr/local/seawall/bin/voidgatectl` | CLI for `/run/voidgate.sock` |
| `voidgate-mkconf` | `/usr/local/seawall/libexec/voidgate-mkconf` | Writes the first config from the default, with the default-route interface |
| `voidgate.service` | `/etc/systemd/system/voidgate.service` | systemd unit, foreground, `-g voidgate` |
| `resty.voidgate` | `/usr/local/seawall/openresty/site/lualib/resty/voidgate.lua` | OpenResty client that pushes L7 bans down to XDP |
| `sw_flowd` | separate component, its own unit | Records the host's outbound flows; voidgate reads its table under `/sys/fs/bpf/seawall/flows` |

voidgate shares the XDP hook through libxdp's dispatcher at priority 10,
ahead of mini-fw and other libxdp programs. If a non-dispatcher program
already holds the hook, voidgate falls back to TC ingress and reports
itself degraded.

## 2. Building and installing

Install the seawall repo first: `make install` refuses to run without the
group `voidgate`, which seawall creates. The build needs sw_flowd's
header, `<sw_flowd/sw_flowd.h>`, the layout of the flow table voidgate
reads: sw_flowd's `sudo make install-header` (or its `make install`)
puts it under `/usr/local/seawall/include`; `make SW_FLOWD_PREFIX=DIR`
looks in `DIR/include` instead. It needs libpkt's headers too,
`<libpkt/parse.h>`, the stack's packet parser: libpkt's `sudo make
install` puts them there; `make LIBPKT_PREFIX=DIR` looks in `DIR/include`.

Host requirements:

- Linux 5.10 or later with BTF (`/sys/kernel/btf/vmlinux`)
- bpffs mounted at `/sys/fs/bpf` (systemd does this); libxdp needs it to
  share the hook
- `CAP_BPF`, `CAP_NET_ADMIN` and `CAP_SYS_ADMIN` at run time (root is
  fine)
- libbpf and libxdp are linked statically, so the host needs neither at
  run time; libelf and zlib stay shared

Build dependencies on Ubuntu 24.04:

```
sudo apt install clang llvm libbpf-dev libxdp-dev libelf-dev zlib1g-dev \
    linux-tools-generic make gcc libtest-base-perl
```

On Amazon Linux 2023 and RHEL 9 (the Perl tests also need
`cpan Test::Base`):

```
sudo dnf install clang llvm libbpf-devel libbpf-static libxdp-devel libxdp-static \
    elfutils-libelf-devel zlib-devel bpftool make gcc
```

Build, test and install:

1. `make`
2. `make test` (unit tests, then the verdict tests as root under XDP, TC
   with tcx, and TC with `cls_bpf`)
3. `sudo make install`
4. `sudo systemctl enable --now voidgate`

`make install` puts the binaries, the default config
(`share/voidgate/voidgate.conf`), `voidgate-mkconf`, the unit and the Lua
client under `/usr/local/seawall`. `PREFIX`, `CONFDIR`, `LUA_DIR` and
`DESTDIR` move them, but the unit always runs
`/usr/local/seawall/sbin/voidgate`. `make install-lua` installs only the
Lua client.

On the first start, the unit's `ExecStartPre` runs `voidgate-mkconf`,
which writes `/usr/local/seawall/etc/voidgate/voidgate.conf` from the
default with `interface` set to the default route's NIC (`ens5` on EC2,
typically `eth0` elsewhere). It never touches an existing config, and
neither does `make install` nor `make uninstall`.

To let a gateway or service use the control socket, add its worker user
to the group `voidgate` and restart that service:
`sudo usermod -aG voidgate kong`. Members get the whole protocol,
`disarm` and `reload` included, so do not add a shared user such as
`nobody`.

## 3. Configuration

The live config is `/usr/local/seawall/etc/voidgate/voidgate.conf` (`-c`
changes it); edit it there, as installs and upgrades never replace it.
The format is one `key = value` per line, `#` starts a comment, and every
key is optional. The shipped `configs/voidgate.conf` explains each key in
its comments.

**Apply** says how a change takes effect: `reload` means
`voidgatectl reload`; `restart` means `systemctl restart voidgate`.

| Key | Default | What it does | Apply |
| --- | --- | --- | --- |
| `interface` | `eth0` | Public RX NIC to attach to. `-i` overrides. Never `lo`. | restart |
| `xdp_mode` | `auto` | `auto` tries native driver XDP, then SKB. `native` / `skb` pin one. | restart |
| `hook` | `auto` | `auto`: XDP, falling back to TC if a non-dispatcher program holds the hook. `xdp`: fail instead. `tc`: always TC. | restart |
| `log_file` | `/var/log/voidgate.log` | Append-only log with `-d` only; in the foreground (the unit) the log is the journal. The parent directory must exist. | restart |
| `pid_file` | `/run/voidgate.pid` | Locked for the daemon's life; `-s stop` reads it. | restart |
| `wake_pps` | `2000` | Aggregate NIC packets/s that arms the gate. | reload |
| `wake_mbps` | `25` | Aggregate NIC Mbit/s that arms the gate. Either one arms. | reload |
| `idle_poll_ms` | `1000` | Userspace tick in ms; `<= 0` becomes 1000. | reload |
| `clear_seconds` | `30` | Quiet seconds, with an empty drop tree, before ACTIVE returns to IDLE. | reload |
| `threshold_pps` | `500` | Per-source packets/s that earns a `/32` or `/128` drop. Keep below `wake_pps`. | reload |
| `threshold_mbps` | `5` | Per-source Mbit/s, same effect. Keep below `wake_mbps`. | reload |
| `ban_time` | `1900` | Seconds a policy or aggregate drop lives. Manual drops never expire. | reload |
| `aggregate_k` | `8` | Dropped hosts in one `/24` or `/64` before the whole prefix is dropped. | reload |
| `local_networks` | (auto) | This VM's CIDRs. Empty takes the NIC's addresses as `/32` and `/128`. Repeated lines add up. Never list the on-link LAN prefix. | reload |
| `allow_networks` | built-in list | Never-drop CIDRs. A non-empty list replaces the built-in one; it does not merge. Repeated lines add up. | reload |
| `allow_ports` | `22` | TCP ports passed on the local side. CSV, at most 8. | reload |
| `remote_map_size` | `262144` | Cap on tracked sources (LRU, not preallocated). | restart |
| `drop_map_size` | `65536` | Cap on drop-tree prefixes (not preallocated). | restart |
| `reply_idle_seconds` | `120` | A flow that has not left for longer is not looked up. | reload |
| `metrics_port` | `9105` | Prometheus on `127.0.0.1`; `0` disables it. | restart |

The built-in allow list is
`169.254.169.254/32, 127.0.0.0/8, ::1/128, fe80::/10, ff02::/16`. When
you set `allow_networks`, copy those in, then add your load balancer and
CDN ranges, on the same line or on further `allow_networks` lines:

```
allow_networks = 169.254.169.254/32, 127.0.0.0/8, ::1/128, fe80::/10, ff02::/16
allow_networks = 35.190.46.17/32
```

The group of the control socket is not a config key: it comes from `-g`
on the command line.

Tuning rules:

- Keep `threshold_pps` below `wake_pps` and `threshold_mbps` below
  `wake_mbps`, so a flood split across sources still drops those sources
  once armed.
- Behind a CDN or load balancer, put the proxy ranges in
  `allow_networks`, or a forged client header can ban your own front
  door.
- Raise `aggregate_k` if many legitimate clients share a NAT `/24`; lower
  it if `voidgate_map_full_total` grows.
- Example: a 1 Gbit/s VM that normally takes 40 Mbit/s might set
  `wake_mbps = 120` and `threshold_mbps = 20`.

A reload with a bad value logs `<file>:<line>: bad value for <key>`,
answers `error: reload failed` and keeps the running config. An unknown
key only logs a warning and is skipped. A reload also lifts any installed
drop, manual ones included, that now covers a `local_*` or `allow_*`
prefix.

## 4. Running the service

In production, run voidgate under systemd; the unit keeps it in the
foreground and restarts it on failure after 2 seconds.

| Task | Command |
| --- | --- |
| Start and enable at boot | `sudo systemctl enable --now voidgate` |
| Stop (detaches XDP) | `sudo systemctl stop voidgate` |
| Restart (needed for `restart` keys) | `sudo systemctl restart voidgate` |
| Apply `reload` keys | `sudo voidgatectl reload` |
| Check the unit | `systemctl status voidgate` |
| Override flags, add paths | `sudo systemctl edit voidgate` |

There is no SIGHUP reload: reload goes through the control socket.
SIGTERM and SIGINT shut the daemon down and detach the program from the
NIC.

Command-line options of `voidgate`:

| Option | Effect |
| --- | --- |
| `-c <config>` | Config file. Relative paths use the launch directory, which the daemon keeps for reloads. |
| `-i <iface>` | Override `interface`. |
| `-g <group>` | Give `/run/voidgate.sock` (mode `0660`) to this group. Takes effect at start; an unknown group only warns and leaves the socket root-only. |
| `-d` | Detach. Waits for startup, prints the daemon PID to stderr, and exits nonzero if startup fails. |
| `-s stop` | Send SIGTERM to the daemon in `pid_file` and wait for it. |
| `-v`, `-vv` | Log every tick; `-vv` also logs each remote source. |
| `-h` | Usage. |

Outside systemd, for a test host:

```
sudo voidgate -d -c /usr/local/seawall/etc/voidgate/voidgate.conf -g voidgate
sudo voidgate -s stop
```

The unit's hardening matters when you move files: `ProtectSystem=strict`
allows writes only to `/sys/fs/bpf` and `/run`. A `pid_file` elsewhere
needs `ReadWritePaths=` added with `systemctl edit voidgate`.

Only one daemon runs at a time. It locks the pid file for its whole life;
a second one exits with `voidgate already running (pid N, <pid_file>)`
before touching the NIC. After a crash, the kernel releases the lock, and
the next start takes over the leftover socket and removes the dead
daemon's program from the NIC.

## 5. Control socket and day-to-day operations

`voidgatectl` sends one command to `/run/voidgate.sock` and prints the
answer; it exits 1 when the daemon answers `error: ...`, so it is safe in
scripts.

| Command | Effect | Typical answer |
| --- | --- | --- |
| `status` | State summary | `state=IDLE armed=0 rx_pps=… rx_bps=… prefixes=0 iface=eth0 hook=xdp-native degraded=0` |
| `stats` | Data-plane counters and rates; `flows` is `sw_flowd` while its table is read, `none` without it | `rx_pkts=… rx_bytes=… passed=… dropped=… non_ip=… map_full=… parse_err=… reply_passed=…` |
| `drops` | Installed prefixes with reason and age | one line per prefix, or `(none)` |
| `arm` | Arm now; re-baselines source rates | `ok` |
| `disarm` | Flush the drop tree, back to IDLE | `ok` |
| `drop <cidr>` | Permanent manual drop (reason 1); arms the gate | `ok` or `error: refused or map update failed` |
| `drop <cidr> ttl=<sec>` | Timed drop (reason 4), 1 s to one year; a repeat only extends it | `ok` |
| `undrop <cidr>` | Remove one prefix | `ok` |
| `reload` | Re-read the config | `ok` or `error: reload failed` |

Drop reasons: 1 manual, 2 policy (source over threshold), 3 aggregate
(`/24` or `/64`), 4 timed (OpenResty bans). The daemon refuses any drop
that covers `local_networks` or `allow_networks`. `disarm` and a daemon
restart forget every drop, manual ones included, so re-apply permanent
drops after a restart.

Daily checks:

1. `voidgatectl status`: expect `state=IDLE`, `degraded=0` and the right
   `iface`.
2. `voidgatectl drops`: review manual drops (reason 1); they never
   expire.
3. `voidgatectl stats`: `map_full` and `parse_err` should not be
   climbing.

Prometheus, when `metrics_port` is positive, is
`http://127.0.0.1:9105/metrics`:

| Metric | Type | Alert on |
| --- | --- | --- |
| `voidgate_armed` | gauge | 1 for longer than an attack should last |
| `voidgate_degraded` | gauge | 1: judging at TC, not XDP |
| `voidgate_rx_pps` | gauge | trend; set `wake_pps` from its normal peak |
| `voidgate_rx_packets_total`, `voidgate_rx_bytes_total` | counter | target down (no scrape) |
| `voidgate_dropped_packets_total` | counter | rate > 0 means an attack is being cut |
| `voidgate_drop_prefixes` | gauge | near `drop_map_size` |
| `voidgate_map_full_total` | counter | any increase: the drop tree or source map is full |
| `voidgate_reply_passed_packets_total` | counter | trend: replies to the host's own flows an armed gate passed |
| `voidgate_flow_table_attached` | gauge | 0: sw_flowd wasn't running when voidgate started |
| `voidgate_flow_table_entries`, `voidgate_flow_table_size` | gauge | entries near size: raise sw_flowd's `table_size` |
| `voidgate_flow_table_evicted_total` | counter | sustained increase: the table is too small |

The listener binds only `127.0.0.1`; scrape it with a local agent or node
exporter textfile, not across the network.

During an attack:

1. `voidgatectl status` and `drops` to see what voidgate has cut.
2. If a whole range is hostile, add it:
   `voidgatectl drop 203.0.113.0/24` (or with `ttl=3600` to have it lift
   itself).
3. If a legitimate client was caught, `voidgatectl undrop <cidr>` and add
   its range to `allow_networks`, then `reload`.
4. After the flood, the gate disarms itself once rx stays below both wake
   thresholds for `clear_seconds` and every drop has expired. Manual
   drops keep it armed until you `undrop` them or `disarm`.

## 6. Logging and the OpenResty bridge

Under the unit voidgate logs to the journal, one entry a line at the
line's own priority: `journalctl -u voidgate`, and
`journalctl -u voidgate -p warning` for its warnings and errors alone.
Run by hand in the foreground, it logs to stderr as
`<local time> voidgate [LEVEL] <message>`, in colour on a terminal.
Only with `-d` does it write to `log_file` (default
`/var/log/voidgate.log`), opened append-only with mode `0644`, in the
same format.

Lines worth watching for:

| Message | Meaning |
| --- | --- |
| `attached <prog> on ifindex N` | Startup succeeded |
| `idle on <iface>, wake_pps=… wake_mbps=…` | Running, gate not armed |
| `armed (…)` / `disarmed (…)` | Gate state change, with the reason |
| `dropped <cidr> (<reason>), …; N listed` / `expired <cidr> (<reason>), …; N left` | Prefixes entered or left the drop tree this tick; past 8 in one tick, counts by reason and the first 8 |
| `refuse drop <cidr> (covers local/allow)` | A drop was blocked to protect the VM or the allow list |
| `drop <cidr> refused: drop list full (N)` | `drop_map_size` reached |
| `degraded: … holds ifindex N's XDP hook …` | Running at TC, not XDP |
| `reloaded <path>` | A reload took effect |

`-v` adds debug lines, among them one `tick` line per poll while armed,
and `-vv` one line per remote source and per idle poll; use them only
while debugging, as they grow the log fast.

Rotation, for `-d`'s file: it is opened with `O_APPEND`, so logrotate's
`copytruncate` works without a restart. If you rotate by renaming,
restart voidgate afterwards; a reload does not reopen the log. A minimal
`/etc/logrotate.d/voidgate`:

```
/var/log/voidgate.log {
    weekly
    rotate 8
    compress
    missingok
    notifempty
    copytruncate
}
```

The OpenResty bridge lets the gateway decide who is abusive
(`limit_req`, failed logins, bot rules) and push that address to XDP as a
timed drop. Install it with `make install-lua`, add the worker user to
group `voidgate`, and see
[`contrib/openresty/nginx.conf`](../contrib/openresty/nginx.conf) and
[`l7-bridge.md`](l7-bridge.md). Operational points:

- Every Lua drop has a ttl; permanent drops are only made with
  `voidgatectl drop`.
- Timed drops never count toward `aggregate_k`, so a few bans behind one
  NAT do not become a `/24` drop.
- The daemon's answers to `ban()` go to the nginx error log; check it if
  bans seem to do nothing.
- Check the real worker group with
  `ps -eo user,group,args | grep 'worker process'`. In a container, the
  worker's gid must match the host's `voidgate` gid.

## 7. Maintenance

The only state worth backing up is the config file and your list of
manual drops; the drop tree lives in BPF maps and is lost on every
restart.

**Changing the config**

1. `sudo cp voidgate.conf voidgate.conf.$(date +%F)` in
   `/usr/local/seawall/etc/voidgate/`.
2. Edit the file.
3. For `reload` keys: `sudo voidgatectl reload`. On
   `error: reload failed`, read the log for the line number; the old
   config is still running.
4. For `restart` keys: `sudo systemctl restart voidgate`, outside an
   attack.
5. Confirm with `voidgatectl status` and
   `journalctl -u voidgate | grep reloaded`.

**Upgrading**

1. Save manual drops: `voidgatectl drops > /root/voidgate-drops.$(date +%F)`.
2. Build and test the new tree: `make && make test`.
3. `sudo make install` (keeps the live config).
4. Compare `share/voidgate/voidgate.conf` with your live config for new
   keys; unknown keys only warn, but new defaults may matter.
5. `sudo systemctl daemon-reload && sudo systemctl restart voidgate`. The
   NIC is unprotected for the short gap between detach and attach.
6. Re-apply the reason=1 drops you saved with `voidgatectl drop <cidr>`.
7. Check `voidgatectl status` shows `degraded=0` and the expected `hook`.

**Testing before rollout**

| Test | Command | Needs |
| --- | --- | --- |
| Unit and verdict tests, all hooks | `make test` | root, BPF |
| Daemon startup and logging | `sudo t/integration/daemon.sh` | root; runs in private namespaces |
| Network-namespace end to end | `sudo t/integration/netns.sh` | root; private namespaces |
| Sharing the hook with other programs | `sudo t/integration/coexist.sh` | root |
| OpenResty client | `sudo t/integration/resty.sh` | `openresty` or nginx with lua-nginx-module; skips otherwise |

**Periodic tasks**

- [ ] Weekly: review `voidgatectl drops` for stale manual drops
- [ ] Weekly: check `voidgate_map_full_total` and `voidgate_degraded`
- [ ] Quarterly: re-check `wake_*` and `threshold_*` against normal peak
  traffic
- [ ] After any change to the VM's addresses or load balancer: `reload`,
  then check `local_networks` in the log (`local network <cidr>` lines)

**Uninstalling:** `sudo systemctl disable --now voidgate`, then
`sudo make uninstall`. The config directory is kept.

## 8. Troubleshooting

Start with `systemctl status voidgate`, `voidgatectl status` and
`journalctl -u voidgate -n 50`; nearly every failure names itself
there.

| Symptom or message | Cause | Fix |
| --- | --- | --- |
| `unknown interface <name>` | `interface` or `-i` names a NIC that does not exist | Set the real public NIC (`ip -o link`); delete the config to let `voidgate-mkconf` redo it |
| `voidgate-mkconf: no default route` | First start before networking is up | Set `interface` in the config by hand |
| `voidgate already running (pid N, …)` | A second daemon was started | Use the running one, or stop it first |
| `another voidgate is already serving /run/voidgate.sock` | A daemon with a different `pid_file` is running | Stop that daemon |
| `pid file … is stale: voidgate is not running` | `-s stop` with no live daemon | Nothing to stop; the file is removed |
| `failed to load BPF object` | Kernel without BTF, missing capabilities, or `MEMLOCK` limit | Check `/sys/kernel/btf/vmlinux`, run as root or under the unit |
| `native XDP attach failed (…), falling back to skb` | Driver lacks native XDP | Normal on some virtual NICs; pin `xdp_mode = skb` to silence it |
| `degraded=1`, `hook=tc` or `tcx` | A non-libxdp program holds the XDP hook (`ip link`, Cilium) | Move that program to libxdp, or accept TC; `hook = xdp` makes this fatal instead |
| `XDP attach: no bpffs at /sys/fs/bpf` | bpffs not mounted | `mount -t bpf bpf /sys/fs/bpf` |
| `voidgatectl: connect /run/voidgate.sock: Permission denied` | Caller not root and not in group `voidgate` | `usermod -aG voidgate <user>`, then restart that service |
| `voidgatectl: connect …: No such file or directory` | Daemon down, or `ctl socket … failed` at start | Start voidgate; read the log |
| `-g voidgate: no such group` | seawall not installed | Install seawall; until then the socket is root-only |
| `error: refused or map update failed` on `drop` | The prefix covers `local_*` or `allow_*`, or the drop map is full | Narrow the prefix; check `drops` count against `drop_map_size` |
| `error: reload failed` | Bad value in the config | Fix the line the log names; the old config keeps running |
| Gate stays armed after the flood | A drop is still installed (manual drops never expire) | `voidgatectl drops`; `undrop` or `disarm` |
| Legitimate clients dropped | Shared NAT or proxy over threshold, or aggregation | `undrop`, add the range to `allow_networks`, `reload`; raise `aggregate_k` |
| A download's or update's server dropped | sw_flowd wasn't running when voidgate started (`stats` shows `flows=none`) | Start sw_flowd, then restart voidgate: it binds the table when it starts |
| SSH lost during an attack | Port not in `allow_ports`, or SSH on a non-local address | Keep `22` (or your SSH port) in `allow_ports`; check `local_networks` |
| `map_full` climbing | Too many sources for `remote_map_size` or `drop_map_size` | Lower `aggregate_k` so `/24` and `/64` drops relieve the tree; raise sizes and restart |
| `ban()` from nginx does nothing | Worker user not in `voidgate`, or address in an allow list | Check the nginx error log for the daemon's answer |

To see what the data plane is doing, run the daemon in the foreground
with `-vv` on a test host, and use `bpftool prog show` and
`bpftool net show dev <iface>` to see what holds the hook.

## 9. Reference

| Path | What |
| --- | --- |
| `/usr/local/seawall/sbin/voidgate` | Daemon |
| `/usr/local/seawall/bin/voidgatectl` | Control CLI |
| `/usr/local/seawall/etc/voidgate/voidgate.conf` | Live config (yours) |
| `/usr/local/seawall/share/voidgate/voidgate.conf` | Shipped default |
| `/usr/local/seawall/libexec/voidgate-mkconf` | First-start config writer |
| `/etc/systemd/system/voidgate.service` | Unit |
| `/run/voidgate.sock` | Control socket, `0660 root:voidgate` |
| `/run/voidgate.pid` | Pid file, locked while running |
| `/var/log/voidgate.log` | Log, with `-d` only; the unit's is the journal |
| `/sys/fs/bpf` | bpffs, used by libxdp's dispatcher (`LIBXDP_BPFFS` overrides) |
| `127.0.0.1:9105/metrics` | Prometheus |

| Signal | Effect |
| --- | --- |
| SIGTERM, SIGINT | Clean shutdown; detaches from the NIC |
| SIGPIPE | Ignored |

Control protocol: one newline-terminated command per connection (at most
254 bytes), a text answer, then close. Answers start with `ok`, data, or
`error:`. The response buffer is 8192 bytes, so a very long `drops` list
is cut short.

Quick commands:

```
voidgatectl status
voidgatectl stats
voidgatectl drops                       # <cidr> reason=N age=<sec>
voidgatectl drop 203.0.113.0/24         # permanent
voidgatectl drop 203.0.113.7 ttl=600    # lifts after 10 minutes
voidgatectl undrop 203.0.113.0/24
voidgatectl disarm                      # flush all drops
voidgatectl reload
curl -s 127.0.0.1:9105/metrics
```

Further reading: [`README.md`](../README.md), [`l7-bridge.md`](l7-bridge.md),
[`contrib/openresty/nginx.conf`](../contrib/openresty/nginx.conf), and the
site at [voidgate.co](https://voidgate.co/).
