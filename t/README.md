# voidgate test suite

Data-driven tests for the XDP data plane and the control socket, written
with Perl [Test::Base] and run against the **real `voidgate` daemon**.
Every case sends real Ethernet frames at a veth pair where the daemon has
its XDP program attached, and reads the verdict from the daemon's own
counters. No mocks, no `BPF_PROG_TEST_RUN`.

[Test::Base]: https://metacpan.org/pod/Test::Base

## Running

```sh
sudo apt install libtest-base-perl   # once; pulls in Spiffy
make
make test                            # t/unit/* + this suite
```

To run just this suite, or only some files, call the runner directly.
Any arguments are passed to `prove`:

```sh
sudo t/bin/run                  # prove -r t/
sudo t/bin/run -v t/v4.t        # one file, verbose
```

Needs root (or `CAP_BPF` + `CAP_NET_ADMIN` + `CAP_SYS_ADMIN` for the
namespaces). Running `prove t/` without the runner skips every file with
`needs the daemon: sudo t/bin/run`.

## How a test runs

```
t/bin/run
  └─ t/bin/create_env.sh: private net, mount (/run, /tmp) and PID namespaces,
     veth pair test0 <-> peer0
  └─ voidgate -d -c t/conf/xdp.conf  XDP attached to test0 (skb mode),
                                     or TC with VG_HOOK=tc
  └─ prove -I t/lib t/
       each block:
         1. voidgatectl-style reset: disarm (flushes blocks), arm, setup cmds
         2. frame built from the spec, sent on peer0 via AF_PACKET
         3. stats read before/after: dropped +1 -> XDP_DROP, else XDP_PASS
```

The socket path `/run/voidgate.sock` is private to the namespace, so the
suite never touches a daemon running on the host. IPv6 is disabled on
`peer0` and it has no IPv4 address, so the kernel adds no ARP, DAD, RS or
MLD frames. Each send also checks that exactly one frame reached XDP. If
anything else arrives, the case fails as `N frames reached XDP (noise?)`
rather than reporting a wrong verdict.

On failure the runner prints the daemon's log, which is where a BPF
verifier rejection shows up.

## Fixture

All files share one daemon, configured by [`conf/xdp.conf`](conf/xdp.conf):

| Setting | Value | Why |
|---|---|---|
| `local_networks` | `198.51.100.10/32`, `2001:db8::10/128` | the "VM" addresses |
| `allow_networks` | built-in defaults + `192.0.2.99/32` | allow-list cases |
| `allow_ports` | `22` | SSH exemption cases |
| `wake_*`, `threshold_*` | 1e9 | never auto-arms, policy never adds blocks |
| `clear_seconds` | 86400 | an armed block is never auto-disarmed |

First-SYN drop's suite, `t/syn/*.t`, runs with `VG_FIXTURE=syn` and
[`conf/syn.conf`](conf/syn.conf), the same but for:

| Setting | Value | Why |
|---|---|---|
| `wake_pps` | 50 | a burst of SYNs on one tick engages first-SYN drop (`--- engage`); the suite's frames, one at a time, never do |
| `idle_poll_ms` | 100 | engaged within a tick of the burst |
| `threshold_pps` | 3 | a source counted against itself is blocked: pure SYNs aren't |
| `syn_guard_bits` | 23 | the smallest filter, 6 MB |

`VG_SYN_ATOMIC=0` takes the entries without atomic OR, as on a kernel
before 5.12.

Blocks start from this state and add blocks themselves. Conventional
addresses used below: `203.0.113.1` and `2001:db8::bad` are the attacker,
`198.51.100.8` and `2001:db8::1` are innocent neighbors.

## Layout

Everything test-related lives under `t/`. `t/bin/run` runs `t/*.t`, or
`t/syn/*.t` with `VG_FIXTURE=syn`: each suite with its own fixture.

| Path | Contents |
|---|---|
| `*.t` | Test::Base suites, run by `t/bin/run` |
| &nbsp;&nbsp;`idle.t` | disarmed gate passes everything, only rx counters move |
| &nbsp;&nbsp;`v4.t` | IPv4 drop, SSH and DHCP exemptions, VLAN, fragments, allow list |
| &nbsp;&nbsp;`v6.t` | IPv6 drop, NDP, SSH and DHCPv6 exemptions |
| &nbsp;&nbsp;`v6-ext.t` | IPv6 extension-header chains, fragments, truncation |
| &nbsp;&nbsp;`cidr.t` | CIDR parsing/masking and the local/allow guard, via `block` |
| `syn/filter.t` | first-SYN drop: the filter's verdicts and retransmission window, the drop LPM ahead of it, pure SYNs never counted against their source |
| `lib/VG/Test.pm` | Test::Base subclass: `run_xdp_blocks`, `run_ctl_blocks` |
| `lib/VG/Packet.pm` | frame builder and raw-socket sender |
| `lib/VG/Ctl.pm` | control socket client (`ctl`, `stats`, `status`) |
| `bin/run` | runs the `*.t` suite against a real daemon |
| `bin/create_env.sh` | private namespaces + `test0`/`peer0` veth; sourced by `bin/run` and `integration/*.sh` |
| `bin/reindex` | renumbers `=== TEST N:` blocks, normalizes spacing |
| `conf/xdp.conf` | daemon fixture for the `*.t` suite |
| `conf/syn.conf` | daemon fixture for `syn/*.t` |
| `conf/idle.conf` | never-wake fixture for `integration/daemon.sh` and `resty.sh` |
| `unit/policy.c` | control-plane unit test, built as `t/unit/policy` by `make` (no root) |
| `unit/cidr.c` | CIDR parser and config CIDR lists, built as `t/unit/cidr` (no root) |
| `unit/syn-plain.sh` | the entries for a kernel before 5.12 have no atomic OR, nor call one that has: read from the object, no 5.10 kernel needed (no root) |
| `integration/daemon.sh` | daemon startup, detach, logging, pid file |
| `integration/resty.sh` | OpenResty client in real nginx (`resty.lua` methods, `ban()`, `-g`); skips without nginx + lua module |
| `integration/netns.sh` | veth flood: IDLE → ACTIVE wake and drop (`VG_HOOK=tc`: at TC) |
| `integration/reply.sh` | with sw_flowd: its table bound when voidgate starts after it (not before), kept across a restart of sw_flowd; a download survives an armed gate, a flood from its server is blocked, manual blocks win; a table of another layout is refused (`VG_HOOK=tc`: at TC); skips without sw_flowd (`SW_FLOWD`, or `../sw_flowd/sw_flowd`) |
| `integration/syn.sh` | first-SYN drop under floods: a UDP flood leaves it in standby, a SYN flood engages it and it stays so, standby after `clear_seconds`, fail-open with userspace stopped, `syn_guard = no` (`VG_HOOK=tc`, `VG_SYN_ATOMIC=0`) |
| `integration/coexist.sh` | sharing the XDP hook: libxdp's dispatcher, TC when another program holds it, leftovers of a killed daemon; skips without clang + xdp-tools |
| `bench/` | manual load generators (`hping3`, `pktgen`) from a netns; not tests |
| `bench/syn-bits.c` | no bit of the filter lost when every CPU writes one cache line at once, by `BPF_PROG_TEST_RUN`; `-p`, the plain writes, shows the race is real. Run by `make test` |
| `bench/syn-cost.c` | ns a SYN of first-SYN drop, warm and with the filter cold under floods of 100k to 10M spoofed SYNs a second, and the share that pass against `syn_guard_fp_est`'s model, by `BPF_PROG_TEST_RUN`: `make t/bench/syn-cost && sudo t/bench/syn-cost` |
| `bench/idle-cost.c` | ns a frame of the XDP program, idle and armed, with and without sw_flowd's table, by `BPF_PROG_TEST_RUN`: `make t/bench/idle-cost && sudo t/bench/idle-cost` |

`make test` runs `t/unit/policy`, `t/unit/cidr` and `t/unit/syn-plain.sh`,
then `sudo t/bin/run` three times: at XDP, at tcx (`VG_HOOK=tc`) and at
classic TC (`VG_HOOK=tc SW_NO_TCX=1`); first-SYN drop's suite at XDP, at XDP
without atomic OR, and at tcx; and `t/bench/syn-bits`. The integration
scripts run separately, each with sudo:

```sh
sudo t/integration/daemon.sh
sudo t/integration/resty.sh
sudo t/integration/netns.sh
sudo t/integration/reply.sh
sudo t/integration/coexist.sh
sudo t/integration/syn.sh
```

## Writing XDP blocks

A `.t` file is three lines of Perl plus data:

```perl
use VG::Test;

run_xdp_blocks();

__DATA__

=== TEST 1: UDP sport 68 from blocked src is not a whitelist
--- setup: block 203.0.113.1/32
--- packets: ipv4 udp 203.0.113.1:68 > 198.51.100.10:80
--- verdict: XDP_DROP
```

`run_xdp_blocks` plans the tests itself (one per block, plus one per
`counters` section). Sections:

| Section | Required | Meaning |
|---|---|---|
| `=== TEST N: name` | yes | test name printed by `prove -v`; `N` is the block's position in the file (see [Numbering](#numbering)) |
| `--- packets` | yes | one packet spec per line (see below) |
| `--- verdict` | yes | one `XDP_PASS` / `XDP_DROP` per packet line |
| `--- setup` | no | control commands, one per line, each must reply `ok` (e.g. `block <cidr>`, `unblock <cidr>`) |
| `--- idle` | no | leave the gate disarmed (`armed = 0`) |
| `--- counters` | no | expected counter deltas summed over the block's packets, e.g. `rx_pkts=1 dropped=0`; only the listed keys are checked |
| `--- engage` | no | engage first-SYN drop first, with a burst of spoofed SYNs from `203.0.113.1`-`20` to port 9 (`conf/syn.conf`) |
| `--- blocks` | no | the cidrs blocked after the packets, in any order; empty: none |

Counter names are the ones from `voidgatectl stats`: `rx_pkts`,
`rx_bytes`, `passed`, `dropped`, `non_ip`, `map_full`, `parse_err`,
`syn_unproven`, `syn_guard_dropped`, `syn_guard_retrans`,
`syn_guard_unready`. A frame first-SYN drop drops is an `XDP_DROP`, as
one the drop LPM drops.

A packets line can also be:

| Line | Meaning |
|---|---|
| `sleep S` | wait `S` seconds; no verdict. The harness waits at least 20 ms after each frame, so a gap wanted is `S` plus about 30 ms |
| `ctl CMD` | a control command, which must reply `ok`; no verdict |
| `Nx SPEC` | `N` frames back to back; one verdict, `XDP_DROP` if all were dropped, `XDP_PASS` if none, else `D of N dropped` |

Single-line sections can use the `--- name: value` form. Longer values go
on the lines after `--- name`:

```
=== TEST 12: overlong extension chain cannot supply exempt ports
--- setup: block 2001:db8::bad/128
--- packets
ipv6 tcp [2001:db8::bad]:40000 > [2001:db8::10]:22 ext=hopopts,dstopts*8
--- verdict: XDP_DROP
```

A block with several packets checks every verdict in order:

```
=== TEST 2: a block is per source
--- setup: block 203.0.113.1/32
--- packets
ipv4 udp 203.0.113.1:12345 > 198.51.100.10:80
ipv4 udp 203.0.113.2:12345 > 198.51.100.10:80
--- verdict
XDP_DROP
XDP_PASS
```

A setup command that does not reply `ok` aborts the file with the block
name and the reply, because that is a fixture bug, not a verdict.

## Packet specs

```
<ipv4|ipv6> <proto> <src> > <dst> [option ...]
```

| Part | Values |
|---|---|
| proto | `tcp` (a SYN, unless `flags=`), `udp`, `icmpv6`; IPv4 also `frag` (header only, no L4) |
| endpoints | IPv4 `203.0.113.1:68`; IPv6 `[2001:db8::bad]:547`; bare address when there is no port (`frag`, `icmpv6`) |

| Option | Meaning |
|---|---|
| `vlan=N` | IPv4 only: insert one 802.1Q tag with TCI `N` |
| `off=N` | IPv4 only: raw `frag_off` field (`off=8` is a non-first fragment) |
| `ext=a,b,...` | IPv6 extension headers in **wire order**: `hopopts`, `dstopts`, `routing`, `ah`, `frag`. `frag:N` sets the raw fragment offset field (`frag:8` is non-first). `name*N` repeats a header |
| `type=N` | ICMPv6 type (`135` is Neighbor Solicitation) |
| `hop=N` | IPv6 hop limit (default 64) |
| `seq=N` | TCP sequence number (default 0) |
| `flags=XY` | TCP flags as letters of `FSRPAU` (default `S`), e.g. `flags=SA` |
| `set@I=V` | after building, set frame byte `I` (0-based, Ethernet header included) to `V`, e.g. to corrupt a length field |

Examples:

```
ipv4 tcp 203.0.113.1:40000 > 198.51.100.10:22
ipv4 udp 203.0.113.1:12345 > 198.51.100.10:80 vlan=1
ipv4 frag 203.0.113.1 > 198.51.100.10 off=8
ipv6 icmpv6 fe80::1 > ff02::1 type=135 hop=255
ipv6 udp [2001:db8::bad]:546 > [2001:db8::10]:547 ext=hopopts,dstopts
ipv6 icmpv6 2001:db8::bad > 2001:db8::10 type=135 ext=dstopts set@55=255
```

Frames are minimal: MACs `02:00:00:00:00:02` → `02:00:00:00:00:01`, a
correct IPv4 header checksum, no L4 checksums, no payload. Useful offsets
for `set@`: the IPv4 header starts at byte 14 (18 with `vlan`), the IPv6
header at 14, and the first IPv6 extension header at 54.

To inspect a frame without the daemon:

```sh
perl -It/lib -MVG::Packet=build -e \
    'print unpack("H*", build("ipv4 udp 203.0.113.1:68 > 198.51.100.10:80")), "\n"'
```

## Writing control-socket blocks

`cidr.t` uses `run_ctl_blocks` instead. Each block disarms (flushing
blocks), sends `input` as one control command, and compares the reply:

```
=== TEST 1: v4 parse masks host bits
--- input: block 10.1.2.3/24
--- expected: ok
--- blocks: 10.1.2.0/24
```

`expected` is the reply without its trailing newline. The optional
`blocks` section is the cidrs of the `blocks` listing afterwards, one per
line. Leave it empty (`--- blocks:`) to assert that nothing was
installed.

## Numbering and spacing

Blocks are separated by three empty lines (the OpenResty convention), so
each case stands apart when reading a file:

```
--- verdict: XDP_DROP



=== TEST 8: UDP sport 67 from blocked src is not a whitelist
```

Every block is named `=== TEST N: <behavior>`, numbered from 1 in each
file, so a failure such as

```
#   Failed test 'TEST 7: UDP sport 68 from blocked src is not a whitelist'
```

leads straight to the block with `grep -n 'TEST 7:' t/v4.t`. Don't
maintain the numbers by hand. Insert or delete blocks anywhere, then
renumber:

```sh
t/bin/reindex t/*.t
```

`reindex` only touches layout: it puts one empty line after the file's
leading comment block, numbers the `===` lines (adding the `TEST N:`
prefix where missing), puts one empty line after `__DATA__`, exactly
three between blocks and none at the end of the file. Files that already follow the rules are left untouched, so it
is safe to run on every file.

## Adding a test

1. Pick the file by area (or create `t/<area>.t` with the three-line
   header above); `prove -r t/` picks up new files automatically.
2. Add a `===` block where it belongs. Name it after the behavior,
   stating the expected outcome ("... is not a whitelist", "... passes
   from blocked src"). Leave the number off, or use any number.
3. Run `t/bin/reindex t/<file>.t`.
4. For a bug fix, run the block against the unfixed build first and make
   sure it fails. A test that passed before the fix proves nothing.
5. Run `sudo t/bin/run -v t/<file>.t`.

If a case needs a different fixture (another `local_networks`, other
`allow_ports`), prefer `--- setup` commands. Change `t/conf/xdp.conf` only
when the control socket cannot express the state, and then re-run the
whole suite.
