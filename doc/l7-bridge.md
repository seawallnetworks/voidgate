# Design: Layer 7 → Layer 3 ban bridge

Let OpenResty, or a gateway built on it (Kong, APISIX), decide which client
is abusive and push that address down to XDP with a drop that expires by
itself. voidgate stays a gate, not a WAF.

Contents:

1. [Problem](#1-problem)
2. [Scope](#2-scope)
3. [Architecture](#3-architecture)
4. [Control protocol](#4-control-protocol)
5. [Timed drops](#5-timed-drops)
6. [The drop list](#6-the-drop-list)
7. [Logging](#7-logging)
8. [State machine](#8-state-machine)
9. [Client: `resty.voidgate`](#9-client-restyvoidgate)
10. [Socket access](#10-socket-access)
11. [Security](#11-security)
12. [Failure modes](#12-failure-modes)
13. [Behaviour changes](#13-behaviour-changes)
14. [Alternatives considered](#14-alternatives-considered)
15. [Future work](#15-future-work)
16. [Tests](#16-tests)

## 1. Problem

voidgate drops floods at XDP based on packet and byte rates. It cannot see
HTTP, so it cannot tell a credential stuffer, a scraper or a slow request
flood from a real user. The web tier can: OpenResty's `limit_req`, failed
logins, bot rules.

But once the web tier has decided, its own enforcement is expensive: every
banned request still costs an accept, a TLS handshake and the HTTP parser
before nginx returns 403. XDP sits in front of all of that, and voidgate
already keeps a drop tree there.

**Goal:** let the gateway push "drop this address for N seconds" into
voidgate's drop tree, without blocking request handling, and keep the
daemon fast when bans arrive by the thousand.

## 2. Scope

In scope:

- **OpenResty**, and gateways built on it such as Kong and APISIX. They run
  the same nginx Lua module, so one client covers them all.
- A drop that **expires by itself**, so a crashed or reloaded gateway never
  leaves bans behind.
- Gateway workers reach the control socket **without running as root**.
- A drop list that stays cheap at its maximum size.

Out of scope:

- **No WAF.** voidgate does not parse HTTP, match signatures or rate-limit
  requests. The gateway detects; voidgate enforces.
- No other deciders yet (fail2ban, HAProxy, ...). Anything that can run
  `voidgatectl drop <ip> ttl=<sec>` works, but nothing else ships (§15).
- No persistence and no per-caller permissions (§11).

The `AGENT.md` invariants still hold:

- no BPF change: a timed drop is an ordinary `drop_v4` / `drop_v6` entry;
- protected prefixes (`local_*`, `allow_*`) are still refused;
- the control plane still decides what is dropped.

## 3. Architecture

```
 ┌─────────────────────────────────────┐         ┌──────────────────────────────┐
 │ OpenResty / Kong / APISIX worker    │         │ voidgate daemon              │
 │                                     │  unix   │                              │
 │  limit_req → 429                    │  socket │  ctl_server.c                │
 │  log phase: resty.voidgate.ban()    │         │    drop <cidr> ttl=N         │
 │    ├─ shared dict: once per window  │         │  policy.c                    │
 │    └─ ngx.timer.at → cosocket ──────┼────────▶│    drop_add()    merge rules │
 │  access phase: ban_now() ───────────┼────────▶│    drop list     pool+lists  │
 │    └─ cosocket now, answer returned │         │    expire_drops() each tick  │
 └─────────────────────────────────────┘         │                              │
                                                 └──────────────┬───────────────┘
                                                                │ LPM map write
                                                 ┌──────────────▼───────────────┐
                                                 │ XDP: drop LPM → XDP_DROP     │
                                                 │ (unchanged)                  │
                                                 └──────────────────────────────┘
```

Only the control plane knows a drop is timed. XDP just looks it up.

## 4. Control protocol

One new form of an existing command:

```
drop <cidr> ttl=<seconds>
```

The dispatcher strips `drop `; `ctl_drop` sees `<cidr>` or
`<cidr> ttl=<seconds>`. **The first word is always the CIDR** and is judged
first, parsed in place with `vg_parse_cidr_len` (no second copy, and a NUL
inside the word is rejected). Only the text after the first space is
options. After `ttl=` only decimal digits are accepted, checked against the
bound digit by digit, so the value cannot overflow.

| Input | Reply |
|---|---|
| `drop 203.0.113.7 ttl=600` | `ok`. A bare address is a `/32` or `/128`, as before. |
| `drop 203.0.113.7 ttl=0060` | `ok`, 60 s: leading zeros are still decimal |
| a bad CIDR, whatever follows: `drop ttl=60 <ip>`, `drop  <ip>` (two spaces), an over-long word | `error: bad cidr` |
| ttl outside 1 … 31536000 (one year), empty, sign, space, hex, trailing text, a number past `uint32`, or any option other than `ttl=` | `error: bad ttl` |
| covers `local_*` or `allow_*`, the drop list is full, or the map write failed | `error: refused or map update failed` |
| `undrop <cidr>` whose kernel delete fails | `error: map update failed` (was a silent `ok`) |

Compatibility:

- `drop <cidr>` without a ttl behaves as before.
- The `drops` line format is unchanged (`<cidr> reason=N age=N`); timed
  drops show `reason=4`. The remaining ttl is deliberately left out, because
  clients and tests anchor on that exact line. Lines are now oldest first.
- `voidgatectl` exits 1 when the reply starts with `error`, or when the
  daemon closes without replying. It used to exit 0 for everything.

## 5. Timed drops

### 5.1 Reasons

| Reason | Name | Installed by | Lifted by |
|---|---|---|---|
| 1 | manual | `drop <cidr>` | `undrop`, `disarm`, a reload that makes it cover a protected prefix |
| 2 | policy | per-remote threshold | `ban_time` after insert |
| 3 | aggregate | `aggregate_k` hosts in one `/24` or `/64` | `ban_time` after insert |
| **4** | **timed** | `drop <cidr> ttl=N` | **its own `expires`**, plus everything that lifts a manual drop |

### 5.2 Dropping a prefix that is already listed

All drops go through `drop_add()` in `src/policy.c`:

| Existing ↓ / new → | manual | timed | policy / aggregate |
|---|---|---|---|
| **manual** | refresh insert time | no change: **manual wins** | no change |
| **timed** | becomes manual (permanent) | `expires = max(old, now + ttl)` | no change |
| **policy / aggregate** | becomes manual | becomes timed, `expires = max(inserted + ban_time, now + ttl)` | no change |

- **Manual wins.** An operator's permanent drop is never shortened by an
  automated ban.
- **A ttl only ever extends.** Re-banning a banned address never shortens
  the ban.
- **A timed drop on a policy drop keeps the longer of the two.** The flood
  detector's decision is never cut short.

### 5.3 Expiry

`expire_drops()` runs on every ACTIVE tick (`idle_poll_ms`, 1 s by
default) and lifts a timed drop once `now >= expires`, using wall-clock
`time()` as `ban_time` does. Expiry only runs while ACTIVE, which is
enough: any drop forces ACTIVE, and the gate cannot disarm while drops
remain.

### 5.4 No aggregation

`maybe_aggregate()` drops a whole `/24` or `/64` once `aggregate_k` listed
drops fall inside it. **Timed drops are not counted.** Web clients cluster
behind carrier CGNAT and corporate egress addresses: a few web bans in one
`/24` plus one flood source must not drop the whole prefix. Manual drops
still count, as before.

## 6. The drop list

### 6.1 Why it changed

The list was an array that grew with `realloc`, and every `drop`, `undrop`
and expiry searched it linearly; expiry searched again for each record it
lifted. A burst of bans made that O(n²):

| 65,536 drops (logging stubbed) | before | after |
|---|---|---|
| add all | ~27 s | ~30 ms |
| expire half in one tick | ~7 s | ~1 ms |
| tick with nothing due (full scan) | 0.3 ms | 0.7 ms |

At ~0.9 ms per ban near the limit, the old list blocked the single event
loop that also runs the tick and the control socket.

### 6.2 Structure

```
drop_pool[2 x drop_map_size]       records, allocated once, never moved
  drop_used                        high-water mark: pool records ever handed out
drop_free   (vg_list)              lifted records, reused first
drop_all    (vg_list)              every listed drop, oldest first   → walks
drop_heads[] (vg_hlist_head)       bucket per prefix hash            → lookups

struct vg_drop_rec {
    cidr, reason, inserted, expires;
    struct vg_hlist_node hash;     /* bucket chain: next, **pprev */
    struct vg_list       all;      /* drop_all, or drop_free when unused */
};
```

- **Pool size** is `2 × drop_map_size`: `drop_v4` and `drop_v6` each hold
  up to `drop_map_size` entries, and `reload` cannot grow them, so the list
  can never need more. A drop past the pool is refused (`drop list full`),
  the same bound the kernel maps already had.
- **Records never move**, so list nodes stay valid while linked, and a
  record stays readable after it is lifted until the next allocation.
- **Memory:** new records come from the high-water mark, not a pre-linked
  free list, so `calloc` pages are only touched as drops are used.
- **Buckets:** the next power of two ≥ the pool size, so chains stay near
  one entry. The hash is FNV-1a over family, prefix length and address;
  the prefix length is part of the key (`/32` and `/24` on the same address
  are separate drops).
- **`src/list.h`** is our own `vg_list` / `vg_hlist`. The kernel's
  `list.h` is GPL-2.0 and voidgate's userspace is Apache-2.0, so the idea
  is reused, not the code.

### 6.3 Operations

| Operation | How | Cost |
|---|---|---|
| find | hash the prefix, walk its bucket | O(1) average |
| add | take a record (free list, else pool), map write, `hlist_add_head`, `list_add_tail` | O(1) |
| remove | **kernel map → hash → list**: map delete, `hlist_del`, `list_del`, onto `drop_free` | O(1) worst case |
| walk (expiry, reload prune, aggregation, `drops`) | safe iteration of `drop_all` | O(n) |
| disarm | flush the maps, then reset heads, lists and `drop_used` | O(buckets) |

**Remove order matters.** The kernel delete comes first: if it fails, the
record stays listed and the next expiry pass retries it. The old code
dropped the record first, so a failed delete left a map entry dropping
traffic that nothing tracked.

**Why not a min-heap for expiry.** The scan of a full list costs ~0.7 ms
per tick, about 0.07 % of a core. A heap would add O(log n) to every insert
and re-ban, plus a heap position per record kept in sync with the lists, to
save that. Not worth it unless a profile says otherwise.

## 7. Logging

### 7.1 The daemon

A burst of bans used to write one timestamped line per drop and per
expiry. On a VM whose clock source is HPET, each timestamp is a system
call, and logging was over 90 % of the cost of a ban burst.

| Event | Default | With `-v` |
|---|---|---|
| drops added since the last tick | one line per tick, naming up to 8: `dropped 203.0.113.7/32 (policy), 198.51.100.0/24 (aggregate); 2 listed`; past 8, counts and the first 8: `dropped 9800 prefixes (manual 0, policy 70, aggregate 3, timed 9727), first 198.18.0.1/32 (timed), …; 41 again, 9812 listed` | plus `drop <cidr> (<reason>)`, and `again` for a re-drop |
| drops expired this tick | one line per tick, the same way: `expired 203.0.113.7/32 (policy); 1 left`, or `expired 9873 drops (policy 70, aggregate 3, timed 9800), first …; 12 left` | plus `expire <cidr> (<reason>)` |
| `undrop` from the socket | `undrop <cidr>` | same |
| reload lifting a protected drop | `reload: undrop <cidr> (now covers local/allow)` | same |
| refusal, full list, map failure | one line each | same |

Refusals and failures stay per prefix: they are rare, and a refusal is
exactly what someone debugging a missing ban looks for. The added-drops
summary is written at the start of the next tick, so drops lifted by a
`disarm` in between are still reported. To see which addresses are banned,
use `voidgatectl drops`.

### 7.2 The gateway

What reaches nginx's error log depends on where a ban fails:

| Failure | Logged by nginx / ngx_lua | Logged by the client or caller |
|---|---|---|
| socket missing (voidgate not running) | `[crit] connect() to unix:/run/voidgate.sock failed (2: No such file or directory)` | `ban()`: its own line; `ban_now()` and methods: `nil, err` to the caller |
| stale socket (voidgate died) | `[error] connect() ... failed (111: Connection refused)` | same |
| daemon hung | ngx_lua's read-timeout line (`lua_socket_log_errors` on, the default) | same |
| daemon refuses (protected address, full list, map failure) | nothing: a normal reply on a working socket | `ban()`: its own line; `ban_now()`: `nil, "error: ..."` |
| bad input (`bad ip`, `bad ttl`) | nothing | `nil, err` from the call itself |

The `connect()` lines come from nginx's core connect code, not from
ngx_lua, so `lua_socket_log_errors off` does not silence them (checked: a
missing socket logs at `crit`, a stale one at `error`). While voidgate is
down, a failed ban therefore shows twice: nginx's line and the client's.
The client and the example keep their line anyway, because the daemon's
refusals, which matter most (a CDN address in `allow_networks`, a full
list), appear nowhere else.

The example logs at `ngx.ERR`, the level nginx's default `error_log` shows:
an `ngx.WARN` line would vanish there. Its health timer logs nothing of its
own; its connect attempt is what makes nginx log the failure once a minute.

## 8. State machine

- A timed drop arms the gate, like a manual one.
- ACTIVE → IDLE still needs an empty drop list, so **the gate stays armed
  while any web ban is live**. ACTIVE parses every packet and updates the
  host and remote maps: more than the idle path, far less than letting the
  request reach nginx. A site that bans steadily will be armed most of the
  time, which weakens "silent unless under attack". Accepted (§14).
- `disarm`, and a daemon restart, forget every timed drop. Nothing is
  persisted.
- `reload` lifts a timed drop that now covers `local_*` or `allow_*`, as it
  does every other drop.

## 9. Client: `resty.voidgate`

`lua/resty/voidgate.lua` is the only Lua client: methods, response parsing,
`ban()` and `ban_now()` in one module that needs nothing beyond
lua-nginx-module. It follows the OpenResty `resty.*` naming convention.

```lua
local vg = require("resty.voidgate")
vg.ban(ip, ttl, { dict = "voidgate_ban", window = 10, client = c })  -- 10s
vg.ban_now(ip, ttl, { client = c })            -- true, or nil, err
vg.drop(cidr, ttl) / vg.undrop(cidr)           -- prefixes, ttl required
vg.status() / vg.stats() / vg.drops() / vg.arm() / vg.disarm() / vg.reload()
vg.new({ path = "/run/voidgate.sock", timeout = 1 })   -- 1s
```

**Which call.** Request code bans one client address; `ban()` and
`ban_now()` take that address and differ only in when they talk to the
daemon. `drop()` / `undrop()` mirror the socket protocol for prefixes.

| | `ban(ip, ttl, opt)` | `ban_now(ip, ttl, opt)` | `drop(cidr, ttl)` |
|---|---|---|---|
| target | one address | one address | any CIDR |
| sends | later, from a timer | now | now |
| phases | all but `init_by_lua*` | cosocket phases | cosocket phases |
| returns | `true` once queued; answer logged | `true`, or `nil, err` | `true`, or `nil, err` |
| deduplication | once per window with `opt.dict` | none | none |

**No permanent drop from Lua.** Every one of these needs a ttl (1 s to one
year); `drop(cidr)` without one is `nil, "bad ttl"` and nothing is sent.
Gateway code that forgets a ttl must not leave a drop nothing will lift.
A permanent drop is an operator's decision: `voidgatectl drop <cidr>`.

**Transport.** `ngx.socket.tcp()` connects to `unix:<path>`, sends one line
and reads with `receive("*a")` until the daemon closes. No keepalive pool:
the protocol is one command per connection.

**Phases.** Plain Lua runs in every phase; what ngx_lua restricts per phase
is I/O. `ban_now()` and the methods (`drop`, `status`, ...) talk to the
daemon over a cosocket, which yields, so they work only where cosockets are
allowed. Elsewhere ngx_lua *raises* `API disabled in the context of ...`,
which would abort the caller's handler; the client catches that and
returns `nil, "no cosocket in this phase, use ban()"` instead.
`ban()` does no I/O itself: it validates its input, does a shared-dict
`add` and queues `ngx.timer.at(0, ...)`, then returns `true` at once. The
daemon request runs later in timer context, where cosockets are allowed,
and its answer goes to the nginx error log, never to the request.

| Context | `ban_now()` and methods (cosocket) | `ban()` (`ngx.timer.at`) |
|---|---|---|
| `rewrite_by_lua*`, `access_by_lua*`, `content_by_lua*` | yes | yes |
| `ngx.timer.*` callbacks | yes | yes |
| `log_by_lua*` | no | yes |
| `header_filter_by_lua*`, `body_filter_by_lua*` | no | yes |
| `set_by_lua*`, `balancer_by_lua*` | no | yes |
| `init_worker_by_lua*` | no | yes |
| `init_by_lua*` (master process) | no | no |

- Call `ban_now()` when the caller needs the daemon's answer, for example
  in `access_by_lua*` or a timer; call `ban()` from anywhere else. Any Lua
  logic can call either: a `log_by_lua*` counter, a Kong or APISIX
  plugin's `log` handler, or another library's callback.
- A periodic aggregator inside OpenResty is a timer: start it with
  `ngx.timer.every` from `init_worker_by_lua*`, and call `ban_now()` or
  the methods directly from its callback.
- Blocking I/O (LuaSocket, `io.*`) is not forbidden, but it stalls the
  worker's event loop and every connection on it, which is why the client
  uses cosockets only.

**Why the log phase.** By then the status is known (429 from `limit_req`,
401 from auth) and the client has already been answered, so the ban adds
no latency.

**Deduplication.** Until the XDP drop lands, one client can send hundreds
of requests, each of which would queue a timer and a socket round trip.
With `opt.dict`, `ban()` first does `dict:add(cidr, true, window)` on a
`lua_shared_dict`, which every worker sees; if the key exists it returns
`true` without sending. The window is 10 s, not the ban's ttl:

- once XDP drops the client, its requests stop reaching nginx anyway;
- a short window self-heals a ban lost to `disarm` or a daemon restart.

**Input.** `ip` must be a bare address: a `/` or whitespace is rejected,
and `/32` or `/128` is appended depending on whether it contains `:`. The
ttl is checked locally (an integer, 1 s to one year); the daemon does the
final CIDR validation.

**Example.** `contrib/openresty/nginx.conf` is a complete config that uses
each pattern in its phase: a health timer started in `init_worker_by_lua*`
(methods in a timer), a honeypot path banned with `ban_now()` in
`access_by_lua*`, `limit_req` 429s banned with `ban()` in `log_by_lua*`,
and a local status page using the methods in `content_by_lua*`. It listens
on 8080, which a master started as an ordinary user can bind, sets
`error_log ... error` explicitly (§7.2), and notes each duration next to
its literal (`600, -- 10m`). No test runs it: it is an example to copy and
adapt, while `resty.sh` covers the client it calls.

**Install.** `make install` (or `make install-lua`, the client only)
copies the file to
`/usr/local/seawall/openresty/site/lualib/resty/`, the Seawall stack's
OpenResty. For another OpenResty, Kong or APISIX, set
`LUA_DIR` to a directory on the gateway's Lua path (Kong:
`lua_package_path`; APISIX: `apisix.extra_lua_path`).

## 10. Socket access

The socket is created `0660 root:root`. voidgate's `-g group` `chown`s it
to that group after `bind`, so gateway workers can connect. The shipped
unit passes `-g voidgate`, a group the seawall repo declares: the
workers' user joins it
(`usermod -aG voidgate kong`), or `-g` names the workers' own group.

| Gateway | Common worker user, group | Set by |
|---|---|---|
| OpenResty | `nobody`, `nogroup` (Debian/Ubuntu) or `nobody` (RHEL) | `user` in `nginx.conf` |
| Kong | `kong`, `kong` | `nginx_user` in `kong.conf` |
| APISIX | `nobody`; `apisix` in its Docker image | `nginx_config.user` in `config.yaml` |

The table assumes a master started as root, which drops its workers to the
`user` directive. A master started as an ordinary user ignores `user` and
runs its workers as itself, so that user joins the group.
Check the real user and group with `ps -eo user,group,args | grep 'worker process'`.
In a container with the socket bind-mounted, the worker's numeric gid must
match the host group's.

- A group missing from `/etc/group`, or a failed chown, stops the start
  before the NIC is touched: a gate whose socket the gateway can't reach
  would look up and refuse every ban. The socket is made `0600` and
  opened to the group only then, whatever the umask.
- Applied at startup; `reload` leaves the socket as it is.
- The systemd unit's capability bounding set gains `CAP_CHOWN`.

## 11. Security

**Trust.** Group members get the whole protocol: `disarm`, `reload`, and
`drop` of any unprotected prefix. A code-execution bug in the gateway can
therefore turn off the gate or drop arbitrary prefixes. Accepted for now:

- the gateway already terminates all traffic, so compromising it is
  already fatal for availability;
- `local_*` and `allow_*` still cannot be dropped, so the VM cannot
  blackhole itself or its management ranges.

**Spoofed addresses.** Behind a CDN or load balancer, a ban keyed on an
unchecked `X-Forwarded-For` lets an attacker ban any address, including the
proxy itself. Two things are required:

- `set_real_ip_from` limited to trusted proxies;
- the proxy ranges listed in `allow_networks`, so the daemon refuses to
  drop them even if a forged header slips through.

## 12. Failure modes

| Failure | Effect |
|---|---|
| daemon down | nginx logs each failed connect (`[crit]` socket missing, `[error]` refused) and `ban()` its own line; `ban_now()` returns `nil, err`; requests are unaffected (§7.2) |
| `ban_now()` or a method in a phase without cosockets | `nil, "no cosocket in this phase, use ban()"`; the caller's handler keeps running |
| daemon restart, or `disarm` | bans are forgotten; the next offending request after the dedup window bans again |
| gateway reload or crash | bans already sent stay until their ttl; nothing to clean up |
| drop list full (`2 × drop_map_size`) | `drop <cidr> refused: drop list full`; the client gets `error: refused or map update failed` |
| kernel map write fails | the record goes back to the pool; `error: refused or map update failed` |
| kernel map delete fails | the record stays listed and expiry retries it next tick; `undrop` answers `error: map update failed` |
| `lua_max_pending_timers` reached | `ngx.timer.at` fails; `ban()` returns `nil, err` |
| daemon slow | the cosocket times out after `timeout` and ngx_lua logs it; with `ban()` only the timer waits, never a request; `ban_now()` waits up to `timeout` in its phase |

## 13. Behaviour changes

For anyone upgrading:

- **`lua/voidgate.lua` (LuaSocket) is removed**, with
  `t/integration/lua.sh`; `resty.voidgate` replaces it. `make install-lua`
  now targets OpenResty's site lualib and `LUA_VERSION` is gone.
- **`voidgatectl` exits 1** on an `error:` reply.
- **`undrop`** answers `error: map update failed` when the kernel refuses
  the delete.
- **`voidgatectl drops`** lists oldest first.
- **Logs:** per-drop `drop` / `undrop` lines from drops and expiry become
  per-tick summaries; use `-v` for the old detail.
- **`drop <cidr> <junk>`** answers `error: bad ttl`; a misplaced or empty
  CIDR answers `error: bad cidr`.
- **No permanent drop from Lua.** `drop(cidr)` without a ttl, in the
  removed LuaSocket client and in the first version of `resty.voidgate`,
  made one; every Lua drop now needs a ttl and `drop(cidr)` answers
  `nil, "bad ttl"`. `voidgatectl drop <cidr>` still makes a permanent drop.
- **Wrong phase:** a `resty.voidgate` method called where cosockets are
  disabled returns `nil, err`; it used to raise and abort the handler.

## 14. Alternatives considered

- **Keeping the ttl in OpenResty** (a shared dict plus a timer that calls
  `undrop`). Rejected: the state is lost on nginx restart, it is
  per-instance, and a crash leaves permanent drops behind.
- **A separate `ban` command.** Rejected: a `ttl=` option on `drop` keeps
  one code path, one refusal rule and one listing.
- **The remaining ttl in the `drops` line.** Rejected for compatibility
  (§4).
- **Enforcing drops while IDLE** (one LPM lookup without arming). Rejected
  for now: it breaks invariant 1 (the idle path does no LPM) and needs a
  BPF change. Revisit if web bans keeping the gate armed costs measurably.
- **A generic Lua client plus an OpenResty wrapper.** Rejected: two modules
  and a pluggable transport add surface for hosts we do not target.
- **Other client APIs.** Module-level `drop()` next to `ban()` read as two
  names for one thing, and `drop(ip)` without a ttl made a permanent drop.
  Hiding the protocol methods behind `vg.new()` was considered; a single
  `ban()` that checks `ngx.get_phase()` was rejected because it would
  return different things in different phases. Chosen: `ban()` and
  `ban_now()` name the difference (queued or now), and a ttl is required
  everywhere.
- **fail2ban.** Deferred. Its most common jail (sshd) would do nothing:
  invariant 4 passes TCP to local `allow_ports` before the drop lookup. It
  bans at low rates that `nftables` already handles cheaply, and correct
  multi-jail unban needs per-drop ownership tags (§15).
- **A min-heap or index-chained hash for the drop list.** See §6.3: the
  heap saves under a millisecond per tick; the index-chained array needed
  relinking on every swap-remove, which the pool and lists avoid.

## 15. Future work

- A restricted second socket that accepts only `drop <host> ttl=` and
  `status`, so the gateway never gets `disarm` or `reload`.
- Tagging each drop with who installed it, so one decider's unban cannot
  lift another's ban (needed before fail2ban support).
- Persisting timed drops across daemon restarts.

## 16. Tests

| Test | Covers |
|---|---|
| `t/unit/policy.c` `test_ttl` | arm on a timed drop, extend-only merge, manual wins both ways, policy → timed keeps `ban_time`, expiry (v4 and v6), no aggregation, `disarm` flush |
| `t/unit/policy.c` `test_drop_index` | 20,000 random adds, re-drops, undrops and expiries; after each, both lists and every `prev` / `pprev` link agree, and lookups match a shadow set |
| `t/unit/policy.c` `test_pool` | full pool refused, lifted record reused, failed map write returns its record, oldest-first order, `disarm` empties the pool |
| `t/unit/policy.c` `test_del_fail` | a failed kernel delete keeps the record and does not spin the expiry loop |
| `t/unit/policy.c` `test_expire_log`, `test_drop_log` | one summary line per tick, per-prefix lines only with `-v`, refusals still per line |
| `t/unit/cidr.c` | `vg_parse_cidr_len`: a word of a longer line, NUL inside the length, over-long input |
| `t/drop-ttl.t` | protocol parsing: v4 and v6, refusal, ttl bounds and digits-only, CIDR-first errors |
| `t/drop-ttl-xdp.t` | a timed drop really drops at XDP; SSH still passes |
| `t/integration/daemon.sh` | `-g` chown, kept on reload, unknown group stops the start; `voidgatectl` exits 1 on error |
| `t/integration/resty.sh` + `resty.lua` | real nginx with workers as `nobody:nogroup`: every method against a real daemon, ttl required and validated, reload; `ban_now()` answers and local rejects; `ban()` from the log phase, 50 requests send exactly one ban; `ban_now()` from the log phase returns an error instead of aborting the handler |

Negative checks in the shell tests use a `refute` helper: under `set -e`,
`! cmd` never fails the script, so `! grep ...` would check nothing.

`resty.sh` needs OpenResty, or nginx with `lua-nginx-module`
(Ubuntu: `nginx-core libnginx-mod-http-lua`), and skips otherwise.
