# AGENT.md — voidgate

Instructions for humans and coding agents working in this repo.

## What this is

voidgate is an **inline XDP DDoS gate for one Linux VM**. It is not
FastNetMon and must not grow FastNetMon’s capture backends.

- Data plane: `src/bpf/voidgate.bpf.c` — pass or drop only. One
  `vg_judge()`, two entries: `voidgate_xdp` in libxdp's dispatcher,
  and `voidgate_tc` at TC ingress when another program holds the XDP
  hook (degraded). The loader loads one.
- Control plane: `src/voidgate.c` + `src/policy.c` — decides CIDRs,
  writes LPM maps.
- No AF_XDP, no packet redirect to userspace, no
  NetFlow/sFlow/pcap/AF_PACKET, no BGP.

The gate is **silent unless the VM is under attack**. Idle path is one
`cfg.armed` load plus coarse rx counters.

## Layout

```
src/bpf/voidgate.h       shared structs (BPF + userspace). No libc.
src/bpf/voidgate.bpf.c   XDP and TC entries (GPL-2.0-only)
src/voidgate.c           daemon
src/voidgatectl.c        voidgatectl (unix socket client)
src/policy.c             IDLE/ACTIVE policy
src/maps.c               libxdp / TC load and attach, LPM helpers
src/config.c             key=value config
src/ipaddr.c             CIDR parse / overlap
src/list.h               intrusive list / hlist (own code: the kernel's
                         list.h is GPL, userspace is Apache-2.0)
configs/voidgate.conf
t/*.t                    XDP verdict / CIDR blocks (Test::Base); see t/README.md
t/lib/VG/*.pm            suite glue: frame builder, ctl client
t/bin/run                real daemon + prove t/ (needs root)
t/unit/policy.c          control-plane unit test
t/unit/cidr.c            CIDR parser + config CIDR lists unit test
t/integration/*.sh       daemon / OpenResty / veth flood / sharing the
                         XDP hook (needs root)
lua/resty/voidgate.lua   OpenResty client (cosocket) + ban(); the only
                         Lua client (Kong / APISIX run on OpenResty)
contrib/openresty/       example nginx.conf (not run by the tests)
```

Generated, do not edit or commit: `src/bpf/voidgate.skel.h`, `*.o`,
binaries.

## Invariants (do not break)

1. **Idle datapath stays cheap.** If `cfg.armed == 0`, XDP must not parse
   Ethernet, must not LPM, must not touch host/remote maps. Only
   `metrics.rx_*` then `XDP_PASS`.
2. **XDP stays attached in IDLE.** Arming is a map write
   (`cfg.armed = 1`), not attach/detach. Detach only on process exit.
3. **Control plane decides drops; XDP only looks them up.** No
   thresholds in BPF.
4. **Whitelist / NDP / SSH before drop.** Never drop IPv6 NDP (types
   133–137 with hop limit 255), `fe80::/10`, `ff02::/16`, TCP
   `allow_ports` when the **local** side is that port (`dport` + dest in
   `local_*`, or `sport` + src in `local_*`), DHCP as an exact port pair
   to a local (or v4 broadcast) dest: UDP 67→68 or 68/67→67, DHCPv6
   547→546 or 546/547→547. A remote source port of 22, 67, 68, 546 or
   547 alone is not a whitelist. Userspace must refuse a drop CIDR that
   covers `local_*` or `allow_*`.
5. **Do not blackhole the VM.** Drop attacker prefixes, not the local
   interface CIDR.
6. **Do not clear `remote_*` on disarm.** BPF has no cheap hash flush.
   Flush `drop_*` only. On the next arm, re-baseline userspace rate
   snapshots so leftover counters are not treated as a new flood.
7. **Shared NIC.** Default verdict is `XDP_PASS`. This is not a SPAN
   tap. No promiscuous mode in v1.
8. **IPv4 and IPv6 together.** Dual LPM, dual host maps, dual remote
   maps. Do not ship v4-only changes.
9. **Do not copy FastNetMon sources** (`/home/ubuntu/fastnetmon` is
   GPLv2). Reuse ideas, not code.

## State machine

Userspace owns state. XDP only reads `cfg.armed`.

```
IDLE  -- wake_pps / wake_mbps or `voidgatectl arm` -->  ACTIVE
ACTIVE -- quiet for clear_seconds AND drop tree empty --> IDLE
`voidgatectl drop <cidr>` forces ACTIVE
`voidgatectl disarm` flushes drops and returns IDLE
```

- `wake_*`: NIC is on fire, turn the gate on.
- `threshold_*`: this remote is part of the attack, install a drop.
- Policy (ACTIVE, 1s): top remotes over threshold → `/32` or `/128`;
  dense clusters → `/24` or `/64`. Manual drops are not auto-expired.
- Timed drops (`drop <cidr> ttl=<sec>`, reason 4) are L7 bans pushed by
  OpenResty. They lift at their own expiry, a re-ban only
  extends them, manual wins over them, and they never count toward
  `aggregate_k` (one NAT /24 of web users must not become a prefix drop).

## Maps

| Map | Type | Written when | Notes |
|-----|------|----------------|-------|
| `cfg` | ARRAY[1] | userspace | `armed`, allow_ports |
| `metrics` | PERCPU_ARRAY[1] | always (rx); armed (dropped, …) | |
| `drop_v4/v6` | LPM_TRIE | ACTIVE | empty in IDLE after disarm |
| `allow_v4/v6` | LPM_TRIE | start/reload | |
| `local_v4/v6` | LPM_TRIE | start/reload | this VM’s CIDRs |
| `host_v4/v6` | PERCPU_HASH | armed | local IPs |
| `remote_v4/v6` | LRU_PERCPU_HASH | armed | attack sources; not flushed |

LPM lookup key prefixlen is 32/128 for a host query. LPM_TRIE maps need
`BPF_F_NO_PREALLOC`.

## Build and test

```
make
make test                         # t/unit/* + sudo t/bin/run
sudo t/integration/netns.sh
sudo t/integration/daemon.sh
sudo t/integration/resty.sh       # needs nginx + lua module; else skips
```

Needs clang, llvm, libbpf, libxdp, bpftool, libelf, libtest-base-perl,
root (or `CAP_BPF` + `CAP_NET_ADMIN`). Kernel 5.10+ with BTF; bpffs.
sw_flowd's installed header, `<sw_flowd/sw_flowd.h>`, from
`$(SW_FLOWD_PREFIX)/include` (default `/usr/local/seawall`; sw_flowd's
`make install-header`). Never copy it here: the table's layout is
sw_flowd's, and voidgate refuses a table of another one. voidgate binds
sw_flowd's pinned maps when it opens the object (`bpf_map__reuse_fd`, in
`skel_open()`): no slots, no re-sync; sw_flowd starts first.
libpkt's installed headers, `<libpkt/parse.h>`, from
`$(LIBPKT_PREFIX)/include` (default `/usr/local/seawall`; libpkt's
`make install`): the stack's packet parser (Seawall proposal 0010).
`vg_judge()` runs `pkt_parse()` and maps its status to a verdict; a
parsing fix goes in libpkt, not here.

Attach (`vg_attach()`): libxdp's dispatcher at priority 10, native or SKB
as the kernel picks (`xdp_mode`). A program that is not a dispatcher on
the hook is never replaced: voidgate goes to TC ingress, first (tcx
`BPF_F_BEFORE`, or classic TC at priority 0x100), and reports degraded.
Its own leftovers from a killed daemon go first. Tests attach in SKB mode
to a veth pair and do not require a real NIC; `VG_HOOK=tc t/bin/run`
runs the verdicts at TC (`make test` runs all three hooks), and
`t/integration/coexist.sh` the hook sharing.

`voidgatectl` talks to `/run/voidgate.sock`. Prometheus (if
`metrics_port` > 0): `127.0.0.1:9105/metrics`.

## Coding rules

- C, no extra libraries beyond libbpf/libxdp/libelf/zlib. `-Wall -Wextra`.
- Formatting: [`code_style.md`](code_style.md) (nginx-based).
- `src/bpf/voidgate.h` is included by BPF and userspace: keep types
  packed/`__u*`, no `stdio`, no pointers to userspace objects.
- BPF file is **GPL-2.0-only** (kernel helpers). Userspace is
  **Apache-2.0**.
- Commit messages: `type: summary` (types: `feature`, `bugfix`, `doc`,
  `tests`, `optimize`, `style`). Wrap every line at 80 characters.
  Example: `style: 4-space indent and braced if/else`.
- Verifier first: bounded unrolls (`VG_MAX_ALLOW_PORTS`; libpkt's
  `PKT_MAX_VLANS` and `PKT_MAX_IPV6_EXT`),
  `data_end` checks before every packet deref. If a BPF change compiles
  but the daemon cannot load the object (see `daemon.log` printed by
  `t/bin/run`), the verifier rejected it — fix the program, do
  not weaken tests.
- After changing `voidgate.bpf.c` or map layouts in `voidgate.h`, rebuild
  the skeleton (`make` does this) and run `sudo t/bin/run`.
  If you change drop/allow/idle behavior, add `===` blocks to `t/*.t`
  (packet specs: `t/lib/VG/Packet.pm`); if you change wake/arm, run
  `t/integration/netns.sh`.
- Unix ctl protocol is one line in, text out: `status`, `stats`,
  `drops`, `arm`, `disarm`, `drop <cidr> [ttl=<sec>]`, `undrop <cidr>`,
  `reload`.
  Replies starting with `error` make `voidgatectl` exit 1. Keep the
  `drops` line format (`<cidr> reason=N age=N`): the Lua client and
  tests anchor on it.
- `reload` re-reads the config file and replaces allow/local maps +
  ports. First it lifts every drop (manual included) that now covers
  `local_*` or `allow_*`, so invariant 4 holds for existing drops too.
  It does not change the attached interface, XDP mode, or map sizes.

## Out of scope until someone explicitly asks

AF_XDP, detaching XDP every idle cycle, 5-tuple conntrack, GRE/GTP/MPLS,
Kafka/ClickHouse, BGP, copying FastNetMon plugins.
