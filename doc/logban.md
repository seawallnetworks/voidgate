# Design: logban, access-log bans for costly URLs

Read nginx's access log, find clients that spend nearly all their requests
on expensive endpoints, and push them down to XDP as timed drops. A
second decider for the [Layer 7 bridge](l7-bridge.md), next to
`resty.voidgate`. It needs no Lua and works with plain nginx.

Contents:

1. [Problem](#1-problem)
2. [Scope](#2-scope)
3. [Architecture](#3-architecture)
4. [Input](#4-input)
5. [Scoring](#5-scoring)
6. [Exemptions](#6-exemptions)
7. [Bans](#7-bans)
8. [Behind a CDN](#8-behind-a-cdn)
9. [`cdn_allow.py`](#9-cdn_allowpy)
10. [Output](#10-output)
11. [Performance](#11-performance)
12. [Security](#12-security)
13. [Failure modes](#13-failure-modes)
14. [Alternatives considered](#14-alternatives-considered)
15. [Limits and future work](#15-limits-and-future-work)
16. [Tests](#16-tests)
17. [Real logs](#17-real-logs)

## 1. Problem

A CC attack (an application-layer flood) does not fill the NIC. A few
hundred clients each loop on one expensive URL, such as a search, a
report or a login, and exhaust the backend at a packet rate voidGate's
flood policy never notices.

The access log already shows the attack. The attacking addresses are near
the top of the request counts for the costly URL, and almost none of
their requests go anywhere else. A browser that searches also loads
pages, CSS, JS and images. A bot that floods `/search` loads nothing else.

**Goal:** turn that observation into a per-address rule, apply it to the
live log, and drop the offenders at XDP for a while.

The same log shows two smaller attacks that cost little each but are
just as easy to recognise: **scanning**, probes for paths the site never
serves (`/.env`, `/.git`, admin panels), mostly answered 404 (§5.6,
§5.7); and **password brute force**, one address posting to the login
form again and again (§5.7). logban drops those too.

## 2. Scope

In scope:

- **nginx access logs**: `combined`, optionally followed by `rt=`,
  `urt=` and `ja4=` fields, or JSON lines (`escape=json`), §4. Kong and
  APISIX logs work when they use either.
- **Per-address rules** over a sliding window, with timed drops through
  the existing `drop <ip> ttl=<sec>` (l7-bridge §4).
- **Watches**: per-address counts of requests by method, path and status
  (404 scans, failed logins, `limit_req` 429s), §5.7.
- **Fingerprint clusters**: many addresses, each under every threshold,
  sharing one JA4 and user agent and sending nearly only costly
  requests, §5.8.
- **Profiles** by path, user agent or JA4 TLS fingerprint, each with its
  own thresholds (§5.4, §5.5).
- **Honey paths**: one request to a path the site never serves bans
  (§5.6).
- **Replay**, to tune thresholds on old logs, **review**, to list what
  would be banned for a person or a console to decide on, **explain**, to show why an address was or
  was not banned, and **follow**, to enforce live (§7).
- **A CDN in front:** its edges are never banned (§8).

Out of scope:

- **No change to the daemon or BPF.** logban is a socket client, like
  `voidgatectl`.
- **No WAF.** No signatures, no request bodies, no challenge pages.
- **No banning of clients behind a CDN.** XDP cannot see them (§8).
- **No distributed detection.** One log, one VM.
- **No persistence.** Offense counts start over on restart (§15).

The bridge's rules still hold: timed drops expire by themselves, are
never aggregated into a `/24` or `/64`, and `local_*` / `allow_*` are
refused.

## 3. Architecture

```
 nginx ──writes──▶ access.log
                       │ tail -F (or replay: files, .gz, stdin)
 ┌─────────────────────▼──────────────────────────────────────────┐
 │ logban.py                                                      │
 │                                                                │
 │  parse_line ──▶ honey path? ──yes──▶ exempt? ──no──▶ ban now   │
 │  (combined or JSON, §4)                                        │
 │                     │ no                          (§5.6)       │
 │                     ▼                                          │
 │                 skip path? ──▶ path report (--top-paths)       │
 │                     │                                          │
 │                     ▼                                          │
 │           allowlisted address? ──yes──▶ not judged (§6.1)      │
 │                     │ no                                       │
 │                     ▼                                          │
 │  profile: path / ua / ja4 (§5.4)                               │
 │  Window: per (address, profile) [total, costly, backend s]     │
 │  and per (address, watch) [hits] (§5.7)                        │
 │  and per (ja4, ua, address) [total, costly] (§5.8)             │
 │  and the site's [requests, backend s] (§5.9)                   │
 │                     │ every step (10 s, over 60 s)             │
 │                     ▼                                          │
 │  attack mode? (§5.9) ──▶ tighter min_costly, backend           │
 │  Judge: ratio | backend | watch | cluster ──▶ crawler? (§6.3)  │
 │                     │                                          │
 │                     ▼                                          │
 │  ban: ttl × 2^offense ──▶ stdout line ──▶ socket (unless -n)   │
 └─────────────────────────────────────────────────┬──────────────┘
                                                   │ drop <ip> ttl=N
                                    ┌──────────────▼───────────────┐
                                    │ voidgate: timed drop (reason │
                                    │ 4) → drop LPM → XDP_DROP     │
                                    └──────────────────────────────┘

 cron ──▶ cdn_allow.py ──▶ /etc/logban/cdn-allow.txt (allow_file, §9)
```

Files, all in `contrib/logban/`:

| File | Role |
|---|---|
| `logban.py` | the decider; one file, Python 3.8+, standard library only |
| `logban.conf` | example config, every key documented |
| `cdn_allow.py` | fetches a CDN's egress ranges into an `allow_file` |
| `test_logban.py` | unit tests for both scripts, and replays of `data/`; no root, no daemon |
| `README.md` | how to run it |
| `data/` | two nginx logs, a config built for one of them, and their README (§17) |

`t/integration/logban.sh` runs logban against a real daemon (§16).

Command line, `logban.py [options] LOG...`:

| Option | Does |
|---|---|
| `-c`, `--config FILE` | config (`key = value`; without one, the defaults and nothing costly: an error) |
| `-n`, `--dry-run` | print bans, send nothing |
| `-f`, `--follow` | follow one log, like `tail -F` (§4.3); `--from-start` reads it whole first |
| `-r`, `--review` | replay and list what would be banned, one row per address; sends nothing (§7.3); not with `-f` |
| `--json` | with `-r`, the list as one JSON object, with any `--top-*` reports in it |
| `-x`, `--explain IP` | explain one address (§7.5); a dry run; not with `-f` or `-r` |
| `--top-paths N`, `--top-clients N`, `--top-ja4 N`, `--top-allowed N` | reports at the end of a replay (§10) |
| `-v`, `--verbose` | exempt clients that matched a rule, and the summary line |

`LOG` may be `.gz` or `-` (stdin); several are read in order.

Config keys (`logban.conf` documents each one):

| Keys | Section |
|---|---|
| `window`, `step` | §5.1 |
| `costly` | §5.2 |
| `default.min_costly`, `default.ratio`, `default.max_backend_seconds` | §5.3 |
| `profile <name>`, `<name>.min_costly`, `<name>.ratio`, `<name>.max_backend_seconds`, `<name>.attack_scale` | §5.4, §5.5, §5.9 |
| `honey`, `honey_ttl` | §5.6 |
| `watch <name>`, `<name>.max`, `<name>.ratio`, `<name>.ttl` | §5.7 |
| `cluster_min_addresses`, `cluster_min_costly`, `cluster_ratio`, `cluster_member_min` | §5.8 |
| `allow`, `allow_file`, `skip`, `crawler`, `crawler_ua`, `crawler_timeout` | §6 |
| `ttl`, `max_ttl`, `offense_memory` | §7.1 |
| `socket` | §7.4 |
| `json_ip`, `json_time`, `json_request`, `json_method`, `json_uri`, `json_status`, `json_ua`, `json_rt`, `json_urt`, `json_ja4` | §4.2 |

`costly`, `honey`, `skip`, `allow`, `allow_file`, `crawler`, `profile`
and `watch` may repeat. In `profile <name>` and `watch <name>`, spaces or
tabs separate the two words.

## 4. Input

### 4.1 Log format

The `combined` format works as is. Two fields appended to it let logban
find costly paths by itself:

```nginx
log_format logban '$remote_addr - $remote_user [$time_local] "$request" '
                  '$status $body_bytes_sent "$http_referer" '
                  '"$http_user_agent" rt=$request_time '
                  'urt=$upstream_response_time';
```

With a JA4 module (FoxIO's `ja4-nginx-module`; take the variable name
from its README), append the fingerprint too:

```nginx
                  'urt=$upstream_response_time ja4=$http_ssl_ja4';
```

| Field | Used for |
|---|---|
| first word | the address that is judged and banned. It **must be the TCP peer** (§8). |
| `$time_local` | window time, timezone included, so replays are exact |
| `$request` | the method and the path, without its query string; a malformed request line gives an empty method and path, still counted |
| `$status` | watches (§5.7) |
| `$http_user_agent` | profile matching only (§5.4); never trusted to exempt |
| `urt=` | backend seconds: the sum of every upstream tried (`0.5, 0.2 : 0.1`) |
| `rt=` | used when `urt` is `-` (nginx answered itself) |
| `ja4=` | profile matching and `--top-ja4` (§5.5); `-` or missing reads as none. `ja4t=` (the TCP fingerprint) is ignored. |

Lines that do not parse are counted and skipped.

### 4.2 JSON

A line that starts with `{` is read as JSON, as `log_format ...
escape=json` writes it; any other line as `combined`, so a file may mix
both (a format change mid-file, or two vhosts). No config is needed when
the fields carry nginx's variable names:

```nginx
log_format logban_json escape=json '{"time_local":"$time_local",'
    '"remote_addr":"$remote_addr","request":"$request","status":$status,'
    '"http_user_agent":"$http_user_agent","request_time":$request_time,'
    '"upstream_response_time":"$upstream_response_time",'
    '"ja4":"$http_ssl_ja4"}';
```

| Value | Fields tried, first present wins | Key to change it |
|---|---|---|
| address | `remote_addr` | `json_ip` |
| time | `time_local`, `time_iso8601`, `msec` | `json_time` |
| request | `request`; else `request_method` + `request_uri` or `uri` | `json_request`, `json_method`, `json_uri` |
| status | `status` | `json_status` |
| user agent | `http_user_agent` | `json_ua` |
| backend seconds | `upstream_response_time`, else `request_time` | `json_urt`, `json_rt` |
| JA4 | `ja4`, `http_ssl_ja4` | `json_ja4` |

Each key takes one field name or several, comma-separated, tried in
order: behind realip, `json_ip = realip_remote_addr` (§8). Values may be
strings or numbers; `-` and empty count as absent, as in `combined`. A
line that is not valid JSON, or lacks an address or a time, is
unparsed. A syslog prefix before the `{` is not stripped.

A line parsed from JSON is the same tuple as from `combined`: tests check
both give the same bans, and the sample `data/clickHouse.access.log`
(14,743 lines) gives identical reports read as JSON or converted.

### 4.3 Reading

- **Replay:** one or more files, read in order. `.gz` and `-` (stdin)
  work. The clock is the log's time, so an hour of log replays in seconds
  and gives the same verdicts each run.
- **Follow (`-f`):** like `tail -F`. Starts at the end of the file unless
  `--from-start` is given, buffers a partial last line, and reopens the
  file when its inode changes (rotation by rename) or it shrinks
  (`copytruncate`). While the log is quiet, the window moves on
  wall-clock time, so a client is still judged when its traffic stops.

## 5. Scoring

### 5.1 Window

Per (address, profile), a running `[total, costly, backend seconds]`
over the last `window` seconds, kept as `window / step` buckets. Watches
(§5.7) and fingerprint clusters (§5.8) keep windows of their own, moved
in step with this one:

- each line adds to the newest bucket and to the running totals;
- at each step boundary the window is **judged**, then the oldest
  bucket is subtracted and dropped;
- a line stamped before the current bucket counts in the current
  bucket. nginx logs a request when it ends, so lines arrive slightly out
  of order;
- a gap longer than the window (a quiet night, a replay of two days)
  judges once, then starts empty;
- end of input judges the last, partial window.

A sliding window, not a fixed one: an attack that straddles a boundary of
a fixed 60 s window would be split in two and could pass both halves.

### 5.2 Costly requests

A request is costly when its path matches a `costly` regex
(`^/search`, `\.php$`, ...). Run `--top-paths N` on a real log to see
which paths cost the most backend time.

A path is costly or not whatever the site's load. A test on measured
backend time (a request is costly when it took at least N seconds) was
dropped (§14): under load every page crosses N, so browsers' ratios rise
just when attack mode lowers the thresholds; when quiet, a cached
expensive endpoint answers under N and is not counted.

### 5.3 Rules

`ratio` and `backend` read their thresholds from the request's profile
(§5.4); `default.min_costly`, `default.ratio` and
`default.max_backend_seconds` when no profile matched:

```
default.min_costly = 100
default.ratio = 0.9
default.max_backend_seconds = 0
```

| Rule | Fires when (defaults) | Catches |
|---|---|---|
| `ratio` | `costly >= min_costly` (100) **and** `costly / total >= ratio` (0.9; `off` turns it off) | bots looping on costly URLs |
| `backend` | backend seconds `>= max_backend_seconds` (0 = off) | a client heavy on the backend whatever it requests |
| `honey` | one request to a `honey` path (§5.6) | scanners probing for `.env`, `.git`, admin panels |
| a watch's name | `<name>.max` requests matching the watch, and optionally `<name>.ratio` of the address's requests (§5.7) | path scans, failed logins, clients nginx is already throttling |
| `cluster` | its fingerprint cluster fires, and it behaves like the cluster (§5.8) | wide, slow botnets: each address under every threshold |

`min_costly` stops a short browsing burst from tripping the ratio. The
ratio is what lets CGNAT and office addresses pass: many users behind
one address send many costly requests, but also many cheap ones.

`max_backend_seconds` reads best as workers: backend seconds in one
window divided by the window is how many backend workers the client keeps
busy on average. `30` in a 60 s window is half a worker. Choose it from
`--top-clients` (§10) on a normal week of logs, not by guessing. A CGNAT
address carries many users' backend time, so it is the first legitimate
client this rule hits; in the synthetic log of §11 it peaks at 146 s,
ten times any single browser.

### 5.4 Profiles

Some clients cannot be judged by the ratio: an app or integration that
calls an API and nothing else has a ratio near 1.0 by design. A profile
gives a class of requests its own thresholds:

```
profile api = ua:^MyShop/        # or path:^/api/v1/; lines with one name OR
api.ratio = off
api.max_backend_seconds = 30     # half a worker per address
```

- **Chosen per request.** The first declared profile whose `path:`,
  `ua:` or `ja4:` regex matches; `default` when none does. `default` is
  always there, set with `default.<key>` lines and no match line.
  `ua:` and `ja4:` are the same on every request of a client, so they
  pick a client; `path:` picks an endpoint, and splits a client across
  profiles: a browser's `/api/v1/` calls go to `api`, its pages to
  `default`, each with its own counters and ratio.
- **Counted apart.** The window is keyed by (address, profile). One NAT
  address with app users and browsers keeps two counters, so the app's
  costly calls do not push the browsers' ratio over the line.
- **Banned as one.** A rule firing in any profile bans the address, and
  clears all its counters. The rule is named after the profile:
  `rule=api.backend`.
- **Thresholds, not exemptions.** A user agent is free to forge. A bot
  that copies the app's gets the app's limits, and
  `api.max_backend_seconds` still bans it. That is why a profile cannot
  turn every rule off: a declared profile in which no rule can fire is a
  config error. `default` may judge nothing, if a profile does.
- **Keys:** `min_costly`, `ratio`, `max_backend_seconds`,
  `attack_scale` (§5.9). A key a profile does not set is `default`'s.
  What is costly, the window and the ttl stay global. A bare
  `min_costly = 100` is refused: write `default.min_costly`.
- **NAT adds up.** A NAT address carrying 30 app users uses 30 users'
  backend time. In a synthetic test, one app install peaked at 4.8 s
  (p99.9), a NAT with ~30 of them at 31.4 s, and a bot forging the app's
  user agent at 379 s: `api.max_backend_seconds = 30` banned the NAT too,
  100 would separate them. Read `--top-clients` before choosing.

### 5.5 JA4

JA4 fingerprints the TLS ClientHello: version, cipher suites,
extensions, ALPN. It is a better signal than a user agent, because a
script has to change its TLS stack to fake it, not one header. A
profile matches it like any other field:

```
profile app = ja4:^t13d2014h2_a09f3c656075_14788d8d241b$     # iOS app
profile app = ja4:^t13d1516h2_8daaf6152771_02713d6af862$     # Android app
app.ratio = off
app.max_backend_seconds = 100

profile api_other = path:^/api/       # API calls from any other stack
api_other.min_costly = 20             # banned fast
```

`api_other` matches by path, so it takes every other stack's `/api/`
calls, browsers' included. Nearly all of them are costly, so on a site
whose pages call `/api/` from the browser, a busy session can reach 20
in a window and be banned. Use it only when `/api/` is for apps; else
raise `api_other.min_costly` to a browser's peak (`--top-clients`).

An exact `ja4:^<fingerprint>$` goes into a set, so an allowlist of
dozens costs one lookup per line; any other `ja4:` is a regex.

**Thresholds, not an allowlist.** "Allow these fingerprints, block the
rest" fails real users:

| Property | Consequence |
|---|---|
| A fingerprint is a TLS stack, not an app | iOS `URLSession` is shared by Safari and every iOS app; OkHttp by every app on that version. Matching keeps out `python-requests`, Go's `net/http` and `curl`, not other apps. |
| OS and library updates change it | release day brings new fingerprints; a hard allowlist would block every updated user |
| Android fleets vary | dozens of fingerprints across OS versions and vendors |
| TLS-inspecting proxies and antivirus re-handshake | their users show the middlebox's fingerprint |
| It can be copied | `curl-impersonate`, `utls`, `curl_cffi` copy iOS or Chrome exactly |
| A CDN terminates TLS | the origin sees the CDN's handshake; take JA4 from the CDN, and check it there |

So a missing fingerprint moves its users to the stricter `api_other`,
which bans only those that also flood, and a copied fingerprint still
meets `app.max_backend_seconds`. Build the list from `--top-ja4` on
shadow logs (§10), not by hand, and run it again after each iOS or
Android release.

Synthetic test (82k lines: 300 app users, 500 browsers, two bots), with
the profiles above and `app.max_backend_seconds = 30`:

| Client | Profile | Result |
|---|---|---|
| a script sending the app's user agent from `python-requests` | `api_other` | banned after 20 costly calls |
| an impersonator with the iOS fingerprint, 0.8 s calls | `app` | banned, `rule=app.backend` |
| app users (peak 5.0 s), browsers | `app`, `default`, `api_other` | none banned |

Blocking unknown fingerprints at request time belongs in nginx, not in
logban or XDP: XDP would have to reassemble and parse TLS, and logban
only sees a request after it was served.

### 5.6 Honey paths

A path the site never serves and no page links to: `/.env`, `/.git`,
`/wp-login.php` on a site without WordPress. No real user asks for one,
and scanners ask for all of them, so one request is enough:

```
honey = ^/(wp-login\.php|xmlrpc\.php|\.env|\.git(/|$))
honey = ^/(phpmyadmin|pma|adminer)
honey_ttl = 900                  # the default: as long as max_ttl
```

- **Banned at once.** On the line itself, stamped with its time, not at
  the next step. One ban per ttl however many probes follow.
- **Matched on the path**, without the query string, like `costly` and
  `skip`. Anchor with `^/`: `/blog/wp-login.php` is not a probe of the
  root. Write `\.git(/|$)`, not `\.git/`, or `/.git` itself is missed,
  and not `\.git`, or `/.github/...` is caught.
- **Before `skip`**, so a broad `skip` cannot hide a probe. Not counted
  in the window or the path report.
- **Exempt as usual:** `allow`, `allow_file` and verified crawlers. A
  CDN edge proxying a scanner is not banned (§8).
- **`honey_ttl`** (900 s, as long as `max_ttl`) starts the ttl: one
  probe is the surest evidence logban has, so a honey ban starts at the
  cap. It doubles per offense like any ban, sharing the count with the
  other rules, once `max_ttl` is raised above it (§7.1). The OpenResty
  example bans a day at once; logban stays short because one infected
  phone behind a carrier's CGNAT address should not cut off everyone
  behind it for long, and a scanner that comes back re-bans itself on
  its next probe.
- **Refused patterns.** A `honey` regex that matches `/` or an empty path
  (a malformed request line) would ban every client: config error.
- A ban that fails on the socket is not retried on a timer. Scanners
  send many probes, and the next one tries again. A refused one is held
  like any other (§7.2).

Do not list a path a real page links to, even a hidden link: browser
prefetching, accessibility tools and mail link scanners follow links. A
link meant as a trap must be `rel="nofollow"` and `Disallow`ed in
`robots.txt`, so well-behaved crawlers stay out. Let nginx answer 404 for
honey paths, so the app never serves them.

### 5.7 Watches

The status is the server's verdict on a request, and some verdicts in
bulk give a client away. A watch counts, per address over the window,
the requests that match all of its conditions, and bans at `max`:

```
watch scan = status:404                       # path scanning
scan.max = 50
scan.ratio = 0.5

watch login = method:POST path:^/login$ status:401|403
login.max = 20                                # password brute force
login.ttl = 900                               # straight to the cap

watch throttled = status:429                  # limit_req said no
throttled.max = 30
```

- **Conditions** are `method:`, `path:` and `status:` regexes, separated
  by spaces, all of which must match. `path` is searched, like `costly`;
  `method` and `status` must match whole, so `status:4..` is any 4xx and
  `status:40` matches nothing. Several lines with one name OR.
- **`<name>.max`** (required) hits in the window ban the address,
  `rule=<name> hits=N`. **`<name>.ttl`** starts its ttl (default `ttl`),
  doubled per offense as usual.
- **`<name>.ratio`** (optional) also requires the hits to be that share
  of all the address's requests in the window. A page with a few missing
  images makes every visit a few 404s, and a NAT address with hundreds
  of visitors reaches 50 of them; a scanner's requests are almost all
  misses. With `scan.ratio = 0.5`, the NAT passes and the scanner does
  not.
- **What is counted:** the same requests as the window. Honey paths are
  checked first, skipped paths and allowlisted addresses are not
  counted, and a verified crawler is not banned. Watches count apart
  from profiles: a profile's thresholds do not change a watch.
- Names follow profile names, must differ from them, and cannot be
  `default`, `ratio`, `backend`, `honey` or `cluster`: the rule names a
  ban line could confuse them with.

Notes for the three examples:

| Watch | Note |
|---|---|
| `scan` | Fill `honey` first: it bans on one probe. `scan` catches the paths nobody listed. Keep the ratio: broken links are common. |
| `login` | Only works if the app answers a failed login with a status the watch lists (here 401 or 403; add others, such as 422, if the app uses them). Many answer 200 with an error page, or 302 back to the form, the same as a success; then drop `status:` and count every POST to the form with `login.ratio = 0.5`: nobody submits it 20 times a minute, and an office address, whose users also load pages, passes. Per address only: credential stuffing spread over many addresses, a few attempts each, is the app's to stop (§15). |
| `throttled` | `limit_req` answers **503** unless `limit_req_status 429;` is set; match what your config sends. The client is already refused by nginx; this moves it to XDP, so its requests stop costing a TLS handshake and a parse. |

A watch has no profile or JA4 condition: add one if a case needs it.

### 5.8 Fingerprint clusters

Every rule above is per address. A botnet of 300 addresses, each sending
12 searches a minute, stays under all of them: in a synthetic test,
none of the 300 was banned. What gives it away is that its members look
alike and do one thing: they share a TLS stack and user agent, and
nearly all of their requests are costly.

```
cluster_min_addresses = 10      # 0 (default) is off
cluster_min_costly = 300        # costly requests of the whole cluster
cluster_ratio = 0.9             # costly share, of the cluster and of a member
cluster_member_min = 3          # costly requests of one member
```

A **cluster** is every address sending one (JA4, user agent) pair, or
one user agent when the log has no `ja4=`. It **fires** when, in one
window, it has at least `cluster_min_addresses` addresses, at least
`cluster_min_costly` costly requests, and a costly share of at least
`cluster_ratio`. Then each **member** with at least `cluster_member_min`
costly requests and its own costly share of at least `cluster_ratio` is
banned, `rule=cluster cluster=<addresses> ja4=... ua="..."`.

Each condition keeps someone safe:

| Condition | Keeps safe |
|---|---|
| cluster costly share | browsers: thousands of real users share Chrome's fingerprint, but load pages and assets, so their cluster's share stays low, and the few among them who only searched are not banned for it |
| member costly share | a real user who happens to share the bots' fingerprint, but browses |
| `cluster_member_min` | an address that sent one or two requests on that fingerprint |
| `cluster_min_addresses` | a single client: per-address rules handle it |
| only profiles with `ratio` on | an app's users: all costly by design (§5.4), one fingerprint; they would form a cluster at once |

Allowlisted addresses are not counted, verified crawlers are not banned,
and `--explain` shows a row per cluster the address is in, with the
reason it was or was not banned.

The test above, with clusters on (126k lines: 1000 browsers on one
Chrome fingerprint, 200 app users, the botnet copying Chrome's user agent
but not its TLS stack, and one real user on the bots' stack):

| | Banned |
|---|---|
| botnet, 300 addresses | all, 290 within 40 s of the cluster crossing its threshold |
| browsers, app users, the real user (its share: 0.23) | none |

**Limits.** A botnet that copies a common browser's TLS stack too
(`curl-impersonate`) joins the real users' cluster, whose share is low,
and passes. Real users of an uncommon stack who only hit costly paths
look like a botnet; keep `ttl` short.

### 5.9 Attack mode

The thresholds above are set for a normal day, high enough that no real
client reaches them. During an attack the site has less room: a bot at
60 searches a minute stays under `min_costly = 100` while it and its
peers keep the backend saturated. Attack mode lowers the volume
thresholds while the whole site is under load, and only then:

```
attack_requests = 20000           # site requests in one window; 0 = off
attack_backend_seconds = 0        # site backend seconds in one window; 0 = off
attack_hold = 300                 # stays on this long after the last step over
default.attack_scale = 0.5        # min_costly and max_backend_seconds times this
```

- **The signal is the log itself.** Every step, the site's requests and
  backend seconds over the window are compared with the two thresholds;
  either one turns the mode on. They are counted from every line that
  reached the backend: allowlisted and skipped requests included (a CDN's
  traffic is load too), banned clients left out (live, XDP drops them,
  so a replay must not count them either). Off, nothing is counted.
- **What tightens.** Every profile's `min_costly` (rounded up, at least
  1) and `max_backend_seconds` are multiplied by its `attack_scale`.
  **The ratio is never scaled:** it is what lets browsers, CGNAT and
  office addresses pass (§5.3), and under load their mix of pages and
  assets is unchanged. A browser does not become a bot because the site
  is busy, so attack mode bans more bots, sooner, not more browsers.
- **What does not.** Watches, honey paths and clusters keep their
  thresholds: they recognise a behaviour, not a volume.
- **Per profile.** `<name>.attack_scale` overrides `default`'s, like
  the other profile keys (§5.4). An app's users are judged by
  `max_backend_seconds` alone; `api.attack_scale = 1` keeps their limit
  when the site is busy, at the cost of a bot forging the app's user
  agent getting it too.
- **Hysteresis.** The mode stays on `attack_hold` seconds after the last
  step over a threshold. Its own bans bring the load down; without the
  hold it would switch off, the bots return when their ttl ends, and it
  switches on again.
- **Visible.** stdout gets `attack on` and `attack off` lines with the
  site's counts (§10), `--explain` an `attack` row, and a ban that only
  the tighter thresholds fired ends in `mode=attack`, also in
  `--review`'s `details`. Those are the bans to check for false
  positives.
- **Choosing the thresholds.** `--top-clients` prints the site's peak
  per window over the replay (§10). Run it on a normal week and set
  `attack_requests` or `attack_backend_seconds` well above that peak:
  a threshold the site reaches on an ordinary evening makes every evening
  an attack.

**Limits.** A NAT address is the first legitimate client a halved
`max_backend_seconds` reaches (§5.3).

## 6. Exemptions

| Exemption | Checked | Matches |
|---|---|---|
| `allow` | every line (cached) | CIDRs; `127.0.0.0/8` and `::1` always |
| `allow_file` | every line (cached) | CIDR files, re-read when replaced |
| `skip` | every line | path regexes: those requests are not judged; a `honey` path is checked first |
| `crawler` | only when a rule fires, and only for a client that claimed a crawler's user agent | reverse DNS suffix, confirmed forward |

### 6.1 Allowlists are applied as lines are read

An allowlisted address can never be banned, so its lines skip the
window. A busy CDN edge then holds no window state and puts no
`skip ... allow` lines in the `-v` output on every step. The result of
the CIDR check is cached per address (65,536 entries, then cleared), so
the cost per line is one dict lookup, not a scan of the list. Allowlisted
traffic still counts in `--top-paths`: behind a CDN, most real traffic is
there. An address that does not parse (`-`, a unix socket) is treated
the same way.

### 6.2 `allow_file`

One CIDR per line, `#` comments, repeatable key.

- **At startup**, a missing or broken file is a config error naming the
  file and line.
- **While running**, the files' inode, mtime and size are checked every
  step. A change re-reads them all, clears the per-address cache, and
  logs `allow_file reloaded: N networks`.
- **A broken update** keeps the old networks, logs
  `allow_file not reloaded`, and is not retried until the file changes
  again.
- An address that becomes allowlisted mid-window is not banned on the
  counts it already has: the check runs again when a rule fires.

### 6.3 Crawlers

A user agent is free to forge, so it never exempts. A client is a
crawler when its reverse DNS name ends in a `crawler` domain
(`googlebot.com`, `search.msn.com`, ...) **and** that name resolves back
to the same address. This is what the search engines document.

DNS is slow, and a reverse zone may not answer at all, so the check is
narrowed three ways:

- **Only when a rule fires** (or a honey path is hit), and the result is
  cached per address.
- **Only for a client that claimed to be a crawler**: at least one of
  its requests carried a user agent matching `crawler_ua` (default
  `(?i)bot|crawl|spider|slurp|google`, which covers Googlebot, its
  `Mediapartners-Google` and `Googlebot-Image`, Bingbot, Yandex, Apple,
  Baidu). Real crawlers always say so. A scanner with a browser's user
  agent is banned with no lookup; a fake Googlebot is looked up, fails,
  and is banned. The match is cached per user agent string.
- **Each lookup gets `crawler_timeout` seconds** (1), reverse and
  forward each, in a thread; one that does not answer in time is "not a
  crawler", and `-v` logs it.

In follow mode a lookup holds up the loop, and with it every other
client's bans. On the Kaggle log (§17.3), checking every candidate made
142 lookups: 79 of the addresses have no reverse DNS, 16 lookups took
over 1 s, up to 10 s each, 104 s in all, and the replay ran 531 s
instead of 274. With the claim and the timeout: 12 lookups, 271 s, the
same bans.

### 6.4 Skipped paths

`skip` paths are left out of the window and of the path report: nothing
sent to them can get anyone banned, a flood included. For clients whose
ratio is near 1.0 by design, use a profile (§5.4) instead. Keep `skip`
for health checks and the like, and rate-limit them in nginx.

## 7. Bans

### 7.1 TTL

```
ttl = min(base × 2^(offenses), max_ttl)        defaults: 60 s, 900 s
```

`base` is the rule's: `ttl` (60 s) for rules, `honey_ttl` (900 s) for
honey, a watch's `<name>.ttl`. No default exceeds `max_ttl`. One set
above it is capped, with a warning at startup:

```
logban: honey_ttl 3600 is above max_ttl 900: capped at 900
``` `offenses` counts earlier bans of the address, and resets
to 0 once the address has been quiet for `offense_memory` (86400 s)
**after its last ban ended**.

**`max_ttl` is 15 minutes.** A ban is a guess, and the guess can be
wrong: a machine that was infected and has been cleaned, a home or
mobile address handed to the next customer, a CGNAT address shared by
many users. While banned, an address cannot show it has changed: its
packets are dropped before logban sees them, so a ban always runs its
full term. A short cap bounds the cost of a wrong guess; a right guess
costs little to repeat, because the offender trips a rule again soon
after its ban ends and is banned again, with the escalation remembered
for `offense_memory`.

Measured on `data/me.access.log` with `data/me.conf`, two weeks:

| `max_ttl` | bans | addresses banned | requests dropped | let through after a first ban | most for one address |
|---|---|---|---|---|---|
| 1 day | 428 | 261 | 25,247 | 290 | 48 |
| 1 hour | 575 | 261 | 25,052 | 485 | 96 |
| **15 minutes** | 624 | 261 | 25,003 | 534 | 96 |

The same addresses are banned; 15 minutes lets about 1 % more of their
traffic through (244 requests in two weeks, against 25,000 dropped) and
bounds a mistake at 15 minutes instead of a day. Raise `max_ttl` where
the trade goes the other way.

**The first ban is a minute** (`ttl = 60`), escalating 60, 120, 240,
480, 900 s. A false positive, a CGNAT address or a browser near a
threshold, costs one minute. The price is paid by an offender that
returns as soon as each ban ends: it gets through until it crosses the
threshold again, a few more times than with longer first bans. Measured
against a 600 s first ban:

| Log, config | `ttl` 600 | `ttl` 60 |
|---|---|---|
| `data/me.access.log`, the 404 watch alone: let through after a first ban | 4,967 | 4,971 |
| `data/kaggle.access.log`, the product scraper: let through after its first ban | 5,693 | 6,288 (its bans: 60, 120, 240 s instead of 600, 900, 900) |

Scanners send a burst and leave, so a short first ban costs nothing
there; the scraper, banned three times in 4.7 days, gets 595 more of
its 38,694 requests through. Honey bans keep `honey_ttl`: one probe is
certain, and starts at the cap.

`offense_memory` is counted from the end of the last ban, not its start.
Counted from the start, as a first version did, the memory ran out
during the longest bans: a ban of a day, as long as the memory, could
never be followed by a repeat in time, and the most persistent clients
fell back to the first ttl.

### 7.2 After a ban

- The address's counts are removed from its profile and watch windows,
  so an expired ban does not fire again on old traffic. Its cluster
  counts stay: they only matter summed over many addresses, and are gone
  one window later, long before the ttl ends.
- It is not judged again until its ttl has passed. In a replay the bot's
  lines keep coming (nothing really dropped them), so expect a second ban
  with a doubled ttl. Live, its packets are dropped at XDP and it
  disappears from the log.
- A ban that fails is printed with `error=` and is **not** counted as an
  offense. What happens next depends on who failed:

  | Failure | Next |
  |---|---|
  | the socket: daemon down, restarting, or it closed without a reply | retried at every step while the rule still fires |
  | the daemon replied `error: ...`: a protected address (`local_*`, `allow_*`), a full drop list, a failed map write | **held** for its ttl, like a ban: the line ends `retry_after=<ttl>s`, and the address is not judged again until then |

  The daemon gives one reply for all three refusals, so logban cannot
  tell a protected address from a full list. Holding is right for both:
  the same request would get the same answer at the next step, and a
  protected address would otherwise be refused, and logged by both
  sides, every 10 s for as long as it sends.

### 7.3 Review

`--review` (`-r`) replays the logs as a dry run and lists the addresses
it would have banned, one row each, for a person or a web console to
decide on. Nothing is sent, whatever the config's socket, so it needs no
privilege. A text table by default; from `data/me.access.log` with a
config that has only the 404 watch:

```
  #  address          bans     ttl requests  costly  ratio   backend  rule          seen (UTC)
  1  213.209.159.175    33     900    10069       0   0.00      0.0s  scan          09-20 04:53 .. 10-04 01:36
  2  80.94.95.211       19     120     5406       0   0.00      0.0s  scan          09-20 01:52 .. 10-04 05:54
  3  74.225.148.80       5      60      437       0   0.00      0.0s  scan          09-23 12:39 .. 09-30 00:01
  4  45.138.12.51        5     120      360       0   0.00      0.0s  scan          09-21 15:15 .. 10-01 16:32
```

`--json` gives the same list to a program, as one compact line;
formatting is left to `jq` or the console. From `data/me.access.log`
with `data/me.conf` (§17.1), through `jq`:

```json
{
 "lines": 34946,
 "unparsed": 0,
 "bans": [
  {"address": "1.15.1.125", "ttl": 3600, "bans": 1, "rules": ["honey"],
   "requests": 49, "costly": 0, "ratio": 0.0, "backend_seconds": 0.0,
   "first": "2026-09-20T00:50:02Z", "last": "2026-09-20T00:50:02Z",
   "details": ["path=/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh"]},
  ...
 ]
}
```

- Every count is the address's whole traffic in the log: `requests`
  is all its lines (any path or status, honey probes, skipped paths,
  and what it sent while banned, which a replay does not drop),
  `costly` those that were costly, `ratio` is `costly / requests`, and
  `backend` its backend seconds. What the window held at each ban is
  `--explain IP`'s job (§7.5).
- Rows are sorted by `bans`, most first, so repeat offenders lead; then
  by `costly`, then by `requests`, then by address: each key breaks the
  ties of the one before (rows 3 and 4 above, on `requests`).
- `ttl` is the replay's last one, doubled for each repeat (§7.1): the
  one to ban with. `seen` spans the first ban to the last, with the
  end's date when it is another day.
- `details` holds what the ban line adds after its rule, up to five:
  `path=/.env` for honey, `hits=N` for a watch, the size, JA4 and user
  agent of a cluster (§10).
- Nothing to ban: `nothing to ban`, or an empty `bans` list.
- With `--top-paths`, `--top-clients`, `--top-ja4` or `--top-allowed`
  (§10), the reports follow the table, or join the JSON object as
  `top_paths`, `top_clients`, `top_ja4` and `top_allowed`, with the fields of their text columns
  (floats to 4 decimals). One parse gives a console the bans and the
  numbers to judge them by.
- To ban a row, the console sends `drop <address> ttl=<ttl>` to the
  socket, as `voidgatectl` or `resty.voidgate` does.
- Not with `-f`: a follow run does not end, and prints bans as it goes.

### 7.4 In the daemon

logban's drops are ordinary timed drops (reason 4), so l7-bridge §5 applies
as is:

- a re-ban only extends: `expires = max(old, now + ttl)`;
- a manual drop of the same address wins and is never shortened;
- timed drops never count toward `aggregate_k`;
- any live drop keeps the gate ACTIVE (l7-bridge §8).

### 7.5 Explain

`--explain IP` (`-x`) answers "why was this address banned", or "why
not", from the logs: a replay as a dry run (nothing is sent, whatever
the config's socket) that prints only that address. Not with `-f` or
`-r`.

```
explain 203.0.113.1: 60 s window, judged every 10 s; times are window ends, UTC
2026-10-03 10:00:10  default      total=38 costly=37 backend=44.4s  under: costly 37 < min_costly 100
2026-10-03 10:00:20  default      total=94 costly=93 backend=111.6s  under: costly 93 < min_costly 100
2026-10-03 10:00:30  default      total=150 costly=149 backend=178.8s  fires ratio
2026-10-03 10:00:30  BAN          rule=ratio ttl=600 offense=1, until 2026-10-03 10:10:30
2026-10-03 10:10:20  banned       59 steps not shown: the replay keeps its requests, XDP would drop them
2026-10-03 10:10:30  default      total=133 costly=129 backend=154.9s  fires ratio
2026-10-03 10:10:30  BAN          rule=ratio ttl=1200 offense=2, until 2026-10-03 10:30:30

summary: 2976 lines: judged default 2976; skipped 0; honey 0
peak window, default: total 150, costly 149, backend 178.8 s
bans: ratio at 2026-10-03 10:00:30, ttl 600, ratio at 2026-10-03 10:10:30, ttl 1200
```

- **One row per judgment step** in which the address has requests in
  the window: per profile its counts and verdict, then per watch its
  hits, then per fingerprint cluster its size, costly share and the
  address's own. A verdict is `fires <rule>`, `fires <rule>, exempt: <why>`, or
  `under:` with the thresholds it missed (`costly 37 < min_costly 100`,
  `costly share 0.83 < ratio 0.90`, `backend 12.0 s < 30.0 s`, `hits 40 <
  max 50`, `hits share 0.10 < ratio 0.50`).
- **Honey hits and bans** get rows of their own; the steps judged while
  banned are folded into one `banned` row (§7.2).
- **Never judged:** an allowlisted address gets one row saying so, and
  the summary repeats it.
- **The summary**: lines judged per profile, skipped and honey lines,
  peak window per profile (outside bans), and every ban.
- **Not in the log**: says so, with the two usual causes. The argument is
  normalized (`2001:DB8:0::BAD` finds `2001:db8::bad`), but nginx logs an
  IPv4 client of an `[::]` listener without `ipv6only` as
  `::ffff:a.b.c.d`.

The verdicts use the same rule tests as the judge (`Profile.rule`,
`Watch.fires`), and a test checks that `--explain` reports the same bans
as a normal run. With no `--explain`, it costs nothing.

## 8. Behind a CDN

XDP sees the TCP peer, and the peer of a proxied request is the CDN's
edge. Hence:

| Traffic | Who can stop it |
|---|---|
| through the CDN | only the CDN: rate limiting, WAF, IP rules. Banning the edge at XDP would cut off every user behind it. |
| straight to the origin, bypassing the CDN | logban and voidGate. This is the usual attack once the origin address leaks. |

Setup:

1. **Log the peer.** With `real_ip_header`, `$remote_addr` is the
   client, which XDP never sees. Log `$realip_remote_addr` first, and the
   client in a field of its own for people to read:

   ```nginx
   set_real_ip_from 173.245.48.0/20;     # ... every CDN range
   real_ip_header   CF-Connecting-IP;
   log_format logban '$realip_remote_addr - $remote_user [$time_local] '
                     '"$request" $status $body_bytes_sent "$http_referer" '
                     '"$http_user_agent" rt=$request_time '
                     'urt=$upstream_response_time client=$remote_addr';
   ```

2. **Allowlist the CDN in logban** with `allow_file`, kept fresh by
   `cdn_allow.py` (§9). `--top-allowed` (§10) then reports how much
   traffic, and how much costly traffic, arrives through it.
3. **Allowlist it in voidGate too.** Add the same ranges to
   `allow_networks`, so the flood policy never drops the CDN and the
   daemon refuses a drop that slips through. The key replaces the
   built-in list (keep those entries) and holds at most 256 entries. The
   README prints the line.

## 9. `cdn_allow.py`

```
cdn_allow.py [-q] cloudflare /etc/logban/cdn-allow.txt
```

Fetches `https://api.cloudflare.com/client/v4/ips` and writes the ranges
one per line, under a header naming the source and the fetch time. It is
meant for cron, so it never makes the allowlist worse:

| Check | On failure |
|---|---|
| HTTP fetch succeeds (20 s timeout) | exit 1, file unchanged |
| JSON has `success: true` and both CIDR lists | exit 1, file unchanged |
| every entry is a valid CIDR string | exit 1, file unchanged |
| both IPv4 and IPv6 ranges present | exit 1, file unchanged |
| no prefix wider than `/8` (v4) or `/16` (v6) | exit 1, file unchanged |
| list is the same as the file's | exit 0, file **not rewritten**, so logban does not reload |

The new file is written next to the target, `fsync`ed, set to mode 0644
and renamed over it. A reader never sees half a file, and a crash leaves
the old one. Another CDN is one parser function and one entry in
`PROVIDERS`.

## 10. Output

stdout, one line per ban:

```
2026-10-03T10:00:30Z ban 203.0.113.1 ttl=600 offense=1 total=150 costly=149 ratio=0.99 backend=178.8s rule=ratio
```

The time is the end of the judged window, from the log's clock; for
`rule=honey`, the probe's own time, followed by `path=<the probe>`. A
failed ban adds `error="..."`, quoting the daemon's reply or the socket
error, and a refusal then `retry_after=<ttl>s` (§7.2):

```
2026-10-03T10:00:20Z ban 198.51.100.10 ttl=600 ... rule=ratio error="error: refused or map update failed" retry_after=600s
```

While attack mode (§5.9) is on, a ban that only its tighter
thresholds fired ends in `mode=attack`. Its switches are lines of their
own, with the site's counts over the window. From
`data/clickHouse.access.log` with `attack_requests = 3000`:

```
2025-10-21T10:34:40Z attack on requests=3090 backend=3724.6s
2025-10-21T11:04:30Z attack off requests=1 backend=0.6s
```

stderr:

| Line | When |
|---|---|
| `allow_file reloaded: N networks` | an `allow_file` changed |
| `allow_file not reloaded, keeping N networks: ...` | the change did not parse |
| `skip <ip> crawler\|allow total=N costly=N` | with `-v`, a verified crawler, or an address allowlisted mid-window (§6.2), matched a rule |
| `skip <ip> allow\|crawler honey <path>` | with `-v`, an exempt client hit a honey path |
| `skip <ip> allow\|crawler <watch> hits=N` | with `-v`, an exempt client reached a watch's `max` |
| `skip <ip> allow\|crawler cluster` | with `-v`, an exempt member of a firing cluster |
| `<key> N is above max_ttl M: capped at M` | at startup, a `ttl`, `honey_ttl` or watch `ttl` set above `max_ttl` (§7.1) |
| `crawler check: <name> timed out after N s` | with `-v`, a lookup gave no answer within `crawler_timeout` (§6.3) |
| `N lines, N unparsed, N allowed, N honey hits` | at the end of a replay, with `-v` or a `--top-*` report |

`--review` prints its table and results on stdout instead of ban lines
(§7.3).

`--top-paths N` then prints the N paths with the most backend seconds,
or the most requests when the log has no timing fields.

`--top-clients N` prints the N (client, profile) pairs with the highest
**peak** backend seconds in one window, with that peak as workers, its requests and costly
requests, all their requests in the log, and whether this run banned
them. Then percentiles of the peaks over the clients that were not
banned, per profile, which is what to choose that profile's
`max_backend_seconds` from:

```
  #  address       profile  backend_s  workers requests   costly   all_req  banned
  1  203.0.113.6   default      406.9     6.78      344      339      2979  yes
 16  100.64.0.1    default      146.0     2.43      694      112     35982
 17  198.51.1.184  default       14.8     0.25       32       12        69

peak backend s per window, clients not banned:
  default    3001 clients  p50 6.4  p90 8.8  p99 11.2  p99.9 13.6  max 146.0
```

Then the whole site's peak in one window, what to set the attack mode
thresholds above (§5.9); in `-r --json`, `top_clients.site`. From
`data/clickHouse.access.log`:

```
site peak per window, banned clients left out: 3090 requests, 3724.6 backend s (62.08 workers)
```

`--top-ja4 N` prints the N most used JA4 fingerprints: requests, share,
distinct addresses, addresses this run banned, backend seconds, and the
user agent each sends most. Then one profile line per fingerprint,
**commented out**: pasting them all would give whatever else is in the
log the app's limits, an attacker's script included.

```
  #  ja4                                   requests  share addresses banned  backend_s  top user agent
  1  t13d2014h2_a09f3c656075_14788d8d241b     41519  50.4%       201      1     4618.4  100% MyShop/5.2.1 (iOS 18.0)
  4  t13d1812h1_85036bcba153_b26ce05bbdd6       909   1.1%         1      0      272.7  100% MyShop/5.2.1 (iOS 18.0)

# Uncomment only your app's fingerprints; lines with one name OR.
# profile app = ja4:^t13d2014h2_a09f3c656075_14788d8d241b$    # 1 banned, MyShop/5.2.1 (iOS 18.0)
```

Read `addresses` with the user agent: row 4 claims to be the iOS app,
but its 909 requests come from one address, while the real iOS stack in
row 1 is spread over 201. Requests without a fingerprint show as
`(none)`.

`--top-allowed N` measures the traffic logban does not judge: per
allowlist (each `allow_file`, and the `allow` keys with loopback), its
requests, their share of all lines, distinct addresses, costly requests
and backend seconds; then the N busiest allowlisted addresses. Behind a
CDN it tells how much arrives through the CDN, and how much of that is
costly, which only the CDN can stop (§8). From `data/me.access.log` with
the Cloudflare list:

```
allowlisted traffic, not judged: 6842 of 34946 lines, 19.6%
source                          requests  share addresses   costly  backend_s
allow_file data/cdn-allow.txt       6842  19.6%       975        0        0.0

  #  address          requests   costly  source
  1  162.158.102.34        754        0  allow_file data/cdn-allow.txt
  2  172.64.200.85         700        0  allow_file data/cdn-allow.txt
```

Every line from an allowlisted address counts, honey probes and skipped
paths included. An address is counted under the first list it is on:
`allow` before the files, the files in config order.

Peaks are sampled at each judgment step. Allowlisted addresses are not
judged, so they are not listed. In a replay a banned client keeps
sending (§7.2), so its peak can be higher than at its ban. Without timing
fields both are by requests. The `--top-*` reports are printed at the
end of a replay, after the bans, the `--review` table or the `--explain`
summary; with `-r --json` they are part of its JSON object (§7.3). A
follow run does not end, so it prints none (§15).

## 11. Performance

One core, CPython 3.12, synthetic log of one hour: 339k lines from 3000
browsers, a CGNAT address and 15 bots. On the two-core VM used, repeated
runs differ by up to 10 %; the "more" rows were measured against the
version before each feature.

| | |
|---|---|
| replay | 6.3 to 6.9 s, about 50k lines/s; 5.5 s with the first version, before profiles, honey, watches, explain and clusters each added a little |
| parsing alone, a log with a new second on most lines (`data/`) | `combined` 83k lines/s, JSON 46k lines/s |
| bans | all 15 bots, each about 30 s into its attack; no browser, no CGNAT |
| allowlist filter (§6.1) | about 8 % of that time |
| one `ua:` profile (§5.4) | about 20 % more: a regex on every line |
| no watches | no cost |
| three watches (§5.7) | about 15 % more |
| clusters off | no cost |
| clusters on (§5.8) | about 18 % more |
| `--top-clients` | about 30 % more: peaks updated every step |
| a log without `ja4=` | no cost: the field is searched only when present |
| `--top-allowed` off | no cost |
| attack mode off (§5.9) | no cost |
| attack mode on | about 4 % more: two sums per line, measured on `data/clickHouse.access.log` ten times over |

A busy single VM logs far fewer lines per second. Past that rate, run it
under PyPy, or sample the log.

Memory grows with the number of distinct addresses in one window: one
small list per address per bucket. The per-address caches are cleared
past 65,536 entries, and the ban table drops expired bans past that size.
The offense counts are kept for every address ever banned (§15).

## 12. Security

- **Forged addresses.** A ban needs the TCP peer to have sent the
  requests, which takes a completed handshake, so a client cannot get a
  third party banned. The exception is a misconfiguration that logs a
  header-derived address (§8). Then the CDN allowlists in logban and
  voidGate are what stop a ban of the CDN.
- **Forged log fields.** nginx escapes `"` in logged variables as `\x22`,
  so a request or user agent cannot end its quoted field early and append
  a fake `rt=` or address.
- **Socket access.** Sending drops needs root or `ctl_socket_group`, and
  that grants the whole protocol (l7-bridge §11). Use `-n` while tuning.
- **Crawler spoofing.** A user agent only decides whether DNS is asked;
  only forward-confirmed reverse DNS exempts (§6.3).
- **Slow reverse zones.** An attacker who runs the reverse DNS of its
  addresses can make lookups hang. They are asked only for a client that
  claims a crawler's user agent, and capped at `crawler_timeout` each.
- **User agent spoofing.** A user agent only picks a profile's
  thresholds, and every profile must be able to ban (§5.4).
- **JA4 spoofing.** Same rule: a copied fingerprint picks thresholds,
  never a pass (§5.5). `--top-ja4` prints its profile lines commented
  out, so an attacker's fingerprint is never allowlisted by a paste.
- **Honey paths and shared addresses.** One probe bans the address: a
  CGNAT address with one infected device in it is banned too, for
  `honey_ttl`. Keep it short, and never list a linked path (§5.6).
- **A poisoned CDN list** could turn logban off for large ranges.
  `cdn_allow.py` fetches over HTTPS and refuses anything wider than `/8`
  or `/16` (§9).

## 13. Failure modes

| Failure | Effect |
|---|---|
| daemon down, or socket not reachable | each ban printed with `error=`, retried every step until it succeeds |
| daemon refuses (address in `local_*` / `allow_*`, drop list full, map write failed) | printed once with `retry_after=`, held for the ttl, then judged again (§7.2) |
| honey ban fails | printed with `error=`; the scanner's next probe tries again |
| a line that does not parse (`combined` or JSON) | counted as unparsed, skipped |
| log rotated | follow reopens the new file; window and bans kept |
| log deleted | follow waits for it to reappear |
| `allow_file` missing or broken at startup | exit 1 with file and line |
| `allow_file` broken by an update | old networks kept, one warning |
| `cdn_allow.py` fetch or check fails | exit 1, old file kept |
| DNS down | crawler check fails closed: the client is banned like any other |
| a reverse zone that never answers | given up after `crawler_timeout`, counted as not a crawler; the thread finishes on its own |
| logban crashes or restarts | live drops expire by themselves; offense counts and the window start over |
| nginx log buffering (`buffer=`, `flush=`) | bans later by the buffering delay |
| clock jump, or replay gap | one judgment, then an empty window |

## 14. Alternatives considered

- **GoAccess.** It reports top hosts and top paths separately, but not
  the paths of each host, which is the signal. Getting that means one run
  per candidate address. GoAccess stays useful as the dashboard people
  look at.
- **Detecting in OpenResty (`resty.voidgate.ban()`).** Faster, since it
  acts on the request itself, but it needs Lua and sees one request at a
  time. The two complement each other: logban needs no Lua and judges a
  client's whole mix of requests.
- **Two passes: top addresses on the costly URL, then each one's other
  URLs.** That computes the same thing as the ratio rule in one pass.
- **A fixed window.** Splits an attack at the boundary (§5.1).
- **Costly by measured backend time** (`slow_seconds`, in an early
  version). Response time follows the site's load, not the request: a
  slow backend made every client's requests costly, browsers' included,
  during an attack, and a fast one let a bot on a cached endpoint pass.
  A hand list of `costly` regexes goes stale as the site changes, but
  does not move with load; rerun `--top-paths` after a release.
- **Checking allowlists only when a rule fires.** That was the first
  version. Bans were the same, but busy CDN edges held window state and
  flooded `-v` output (§6.1).
- **Checking crawlers as lines are read.** That is a DNS lookup per new
  address.
- **Honey paths only in nginx** (the OpenResty example's `ban_now()`).
  Faster, at the request itself, but it needs Lua. logban gives plain
  nginx the same trap; with OpenResty, both can run.
- **fail2ban for the status cases.** Its nginx jails are regexes on the
  log with a count over a time window, which is what a watch is. A watch
  shares logban's window, allowlists, crawler check, refusal handling and
  offense count, and needs no second daemon; l7-bridge §14 has why
  fail2ban was not a decider.
- **Clusters by network prefix** (many bans in one /24). Botnets rent
  residential proxies spread over the internet, and CGNAT puts real
  users in one prefix; voidGate already refuses to aggregate timed
  drops for that reason (l7-bridge §5.4).
- **Clusters by user agent alone** when JA4 is logged. The user agent is
  one header a script sets to Chrome's; the TLS stack it rarely changes.
- **Separate rules per case** (`scan_404 = 50`, `login_fail = 20`).
  Every site's login path and failure status differ; one generic shape
  covers them, and the next case, without code.
- **Picking bans in the terminal** (the first `--review`: a prompt for
  `a`, `n` or row numbers). Bans are decided in a web console; a list in
  text or JSON serves both a person and a program.
- **A hit count for honey paths** (ban on the 3rd). A real user never
  sends even one, and scanners send dozens: one is enough.
- **A hard JA4 allowlist** (block every other fingerprint). Blocks
  users after an OS update, behind a TLS-inspecting proxy, or on an
  uncommon Android build, and copied fingerprints pass it (§5.5).
- **JA4 in XDP.** Means reassembling and parsing TLS from packets;
  voidGate only looks prefixes up.
- **Exempting API clients by user agent.** Their user agent is stable,
  but anyone can send it; it would be a free pass. Profiles use it to
  pick thresholds instead (§5.4).
- **One profile per address** (by its first request, or its most common
  user agent). A NAT address mixes apps and browsers; counting per
  (address, profile) keeps each mix honest.
- **Pricing requests by their path's typical time** instead of measured
  backend time. A slow, overloaded backend inflates every client's
  backend seconds during an attack. Not done yet (§15).
- **Fetching CDN ranges inside logban.** A network dependency in the ban
  loop, and a failure mode in every start. A separate cron job with
  atomic replace keeps logban offline.
- **A Python client library** (like `resty.voidgate`). Deferred: logban
  is its only Python user, and its socket code is one short function.
  Worth it with a second Python decider, such as a CDN-API action.
- **awk.** Smaller, but sliding windows, ttl escalation, allowlist
  reloads and tests are awkward in it.

## 15. Limits and future work

Limits:

- **Credential stuffing over many addresses.** A few login attempts
  per address stay under any per-address watch, and the requests are
  cheap, so clusters (§5.8) do not count them unless the login path is
  `costly`. The app must limit attempts per account.
- **Slow, wide botnets that impersonate a browser.** Clusters (§5.8)
  catch a botnet with its own fingerprint. One that copies a common
  browser's TLS stack and user agent hides among real users; that needs
  a global signal: `limit_req` on the endpoint, or a challenge page.
- **Delay.** Up to one `step` after the threshold, plus log buffering.
- **Clients behind a CDN** cannot be banned at XDP (§8).

Future work:

- **A CDN-API action**, banning by real client address at the CDN
  (Cloudflare IP Access Rules), with the Python client library from §14.
- **More CDN providers** in `cdn_allow.py`.
- **Typical cost per path**, learned from quiet periods, so the backend
  rule does not tighten on everyone when the backend slows down, and a
  path whose typical time is high is costly without a `costly` regex.
  A request is priced by its path's median backend time, not its own,
  so neither the site's load nor the attacker's moves it. Learning
  stops in attack mode. Not a threshold scaled by the site's current
  load: the attack's own load would raise it, and its requests would
  stop counting. Open: path keys (no query string, numeric and hex
  segments collapsed, the table capped), a path with no history
  (measured time outside attack mode, or not costly), and warm-up after
  a restart (regexes only, unless the table is saved).
- **Profiles by a hashed API key**, logged as a field and matched like
  `ja4:`, for APIs that issue keys.
- **Persisting offense counts** across restarts, and pruning them after
  `offense_memory` (today they live as long as the process).
- **A systemd unit** for follow mode.
- **`--top-*` reports in follow mode**, on a signal: today a follow run
  prints none.
- **Syslog-prefixed JSON**: a prefix before the `{` is not stripped.

## 16. Tests

`python3 contrib/logban/test_logban.py`, also run by `make test`. No root,
no daemon, about 5 s, most of it `DataTest` replaying the real log.
`DocTest` fails when this document misses a new option, key or test
class: update it with the code.

`sudo t/integration/logban.sh` runs logban against a real daemon in
private namespaces, about 10 s. Not part of `make test`, like the other
integration scripts.

| Test class | Covers |
|---|---|
| `ParseTest` | combined format, `urt` with several upstreams, `urt=-` falling back to `rt`, IPv6, timezones, garbage and malformed request lines |
| `JudgeTest` | bot banned, browser not; IPv6; `min_costly` and `ratio` boundaries; sliding window; a slow request on a cheap path not costly; rule `backend`; `skip`; `allow`; forward-confirmed crawler versus a fake; one ban per ttl; ttl doubling and `max_ttl`; `offense_memory` counted from the ban's end, so escalation holds at `max_ttl`; failed ban retried; a refusal held for its ttl, logged once, no offense, judged again after; late lines; `--top-paths` |
| `ConfigTest` | the example `logban.conf` loads; unknown keys, bad values and a config with nothing costly are errors |
| `AllowFileTest` | allowlisted addresses kept out of the window but in the path report, one allowlist check per address; missing or broken file at startup; reload on replace; broken update keeps the old list; counts made before the reload excused |
| `SocketTest` | the exact `drop <ip> ttl=N` sent; `ok`; a daemon's `error:` reply is a `Refused`; no reply and no daemon are not |
| `FollowTest` | follow across a rename rotation, counts kept |
| `TopClientsTest` | peak backend seconds, requests and all requests per client; workers column; percentiles over clients not banned; banned clients flagged; allowlisted clients absent; no timing falls back to requests; off unless asked; the report's data matches its text, JSON floats rounded |
| `ProfileTest` | profile keys inherit and override; config errors (field, regex, name, reserved `default`, undeclared, bounds, a profile that cannot fire, all rules off); first declared wins, `ua:` and `path:`, no user agent; an app passes with `api.ratio = off` but the same traffic is banned without the profile; a forged user agent still banned by `api.backend`; one NAT address counted apart; a ban clears every profile's counters; `--top-clients` per profile |
| `Ja4Test` | `ja4=` parsed, `-` / empty / missing as none, `ja4t=` ignored; exact fingerprints held as a set, other `ja4:` as regexes, exact means exact; known stacks pass while a script with the app's user agent and a plain-HTTP client are banned by `api_other`; a copied fingerprint banned by `app.backend`; `--top-ja4` columns, share, banned count, commented paste lines that load once uncommented; no `ja4=` in the log; off unless asked |
| `WatchTest` | method and status parsed, empty method for a malformed request; `scan` at `max` and below it; the window slides; `ratio` lets a NAT with missing images pass and bans a scanner; `login` counts POST 401 and 403, not GET, 200, 422 or another path; without `status:`, every POST, its ratio banning a brute-forcer answered 200 and passing an office that also loads pages, which is banned without it; `throttled` on 429; OR lines and a status regex, `ttl`; spaces or tabs in `watch <name>` and `profile <name>`; allowlisted and skipped requests not counted; a verified crawler not banned; one ban clears every counter; a refusal held; config: values, watch-only and honey-only configs, errors (no or zero `max`, unknown field, empty condition, bad regex, reserved names (`honey`, `cluster`) and bad names, undeclared, profile key on a watch and watch key on a profile, a name used for both, `ttl` and `ratio` bounds) |
| `CrawlerTest` | no lookup for clients with a browser's user agent; a fake Googlebot looked up and banned; one crawler request is enough to be checked later; a 2 s reverse zone given up after 0.2 s, three clients in under 1.5 s, logged with `-v`; the user agent cache, nothing tracked without a crawler list; `crawler_ua` default covers the usual crawlers and not a browser; config errors. Removing the timeout, or the claim, makes a test fail. |
| `HoneyTest` | first hit bans now with `honey_ttl`, `rule=honey path=`, kept out of the window and path report; anchored patterns hit `/.env`, `/.git`, `/.git/config` and miss `/.github`, a nested `wp-login.php`, a query string; one ban per ttl; escalation and `max_ttl`; ttls above `max_ttl` capped with a warning, honey escalating from 900 once `max_ttl` is raised, no default above another (600, 900, 900); offenses shared with the other rules; `allow`, loopback, verified crawler, bad address exempt; wins over `skip`; a failed ban retried by the next probe; shown in `--review`; config: refused patterns, `honey_ttl` bounds only with honey paths |
| `ExplainTest` | under, fires and BAN rows with their times, folded banned steps, summary; the same bans as a normal run; `under:` reasons (costly share, backend); allowlisted: never judged; verified crawler: exempt; honey, skipped, two profiles and a watch in one replay; watch ratio reason; not in the log; CLI: IPv6 normalized, the config's socket never used, bad address, refused with `-f` and `--review` |
| `ClusterTest` | a 30-address botnet each under every threshold: no ban by per-address rules, all banned by the cluster, ban line with size, ja4 and ua; user agent alone without `ja4=`; 50 browsers on one stack pass; search-only users inside a browser cluster pass; a member that browses and one with 2 costly requests pass; below `cluster_min_addresses`, below `cluster_min_costly`, spread over 10 minutes; ratio-off profiles not clustered; allowlisted not counted, verified crawlers not banned; off by default; `--explain` rows; config bounds only when on. Each of the three safety conditions was removed in turn and a test failed. |
| `AttackTest` | off by default, nothing counted; site load turns it on: a slow bot under `min_costly` banned with `mode=attack` while browsers pass, nothing below the threshold; a bot the normal thresholds catch is not tagged; `attack_hold` and a hold of 0, switches logged with their times; by backend seconds; banned clients not counted as load; `<name>.attack_scale = 1` keeps an app's limit; scaled limits rounded up, at least 1; config defaults and bounds; `--explain` rows; the site peak in `--top-clients`, text and JSON |
| `JsonTest` | the same tuple as `combined` for the same request; `urt` with several upstreams, `-` falling back to `rt`, both absent; `ja4` from either name, `-` as none; `time_iso8601` with offsets and `msec` as string or number; `request_method` + `request_uri`; unparsed (cut short, no address, bad or wrong-typed time); `json_*` keys; the same bans in each format and mixed in one file; every line of the `data/` sample parses |
| `TimeTest` | the `time_local` fast path equals `strptime` (also checked on 20,000 random stamps and offsets while writing it); out-of-range and misshapen stamps rejected |
| `DataTest` | replays of `data/` (§17): with a copy of `data/me.conf` as committed (editing the file to experiment does not break it), 261 addresses banned, all by honey, no Cloudflare edge, no address that loaded the game, over 70 % of requests dropped, `80.94.95.211` banned before its `.git` downloads; without the Cloudflare allowlist, over 100 edges banned; the generated JSON sample parses whole and bans nothing |
| `AllowedTest` | allowlisted traffic per source (an `allow_file`; `allow` with loopback): requests, share, addresses, costly, backend seconds, honey probes and skipped paths included, other clients not; the busiest addresses, at most N; the text; after an `allow_file` reload, a dropped range is judged and no longer counted; off unless asked; in the `-r --json` object |
| `ReviewTest` | one row per address, most bans first, then most costly; `requests`, `costly` and `ratio` are the address's whole traffic, all costly for a bot (500 of 500), no `total`; a span over days shows both dates; ttl doubled for a repeat, a honey ban with its ttl; the JSON fields, times and `details`, one compact line; nothing to ban, as text and JSON; CLI: `-r --json` never uses the config's socket, the three `--top-*` reports inside its JSON object, as text after the review table and after the `--explain` summary, `--json` alone and `-r -f` refused |
| `DocTest` | this document keeps up with the code: every command-line option, config key and test class appears in it, every `§` reference and `#` link has its heading, and every config example (§5.4 to §5.8) loads. A self-check feeds it a broken copy and expects each gap reported, and requires at least five examples, so a broken checker cannot pass. |
| `CdnAllowTest` | Cloudflare JSON parsed and sorted; refused inputs (failure flag, a family missing, too wide, bad CIDR, wrong type, HTML); write, no rewrite when unchanged, failure keeps the file, no temp files left |

| `t/integration/logban.sh` | Covers |
|---|---|
| replay | ratio bans (IPv4 and IPv6), a honey ban (from a JSON line in the same file), a `scan` watch ban and a 12-address cluster land as `reason=4` drops; a browser is not dropped; a flood from the protected `local_networks` address is asked once (one logban line with `retry_after=600s`, one `refuse drop` line in the daemon log), not every step |
| follow | daemon stopped: a live flood's ban fails with `error=` and is retried every step; daemon started: the next retry lands the drop |

That XDP then drops the address is `t/drop-ttl-xdp.t`'s job: logban sends
the same `drop <ip> ttl=N` as `voidgatectl`. Against the logban from
before refusals were held (§7.2), the test fails: the protected address
was asked 29 times.

## 17. Real logs

`contrib/logban/data/` holds two nginx logs, replayed by `DataTest`, and
can hold a third, large one that is not in git (§17.3).

### 17.1 `me.access.log`

A real `combined` log, no timing fields, of a small static site (a
browser game: `/`, `*.js`, `style.css`), 20 Sep to 4 Oct 2026: 34,946
lines from 1,983 addresses.

- **Mostly scanners.** 92 % of answers are 4xx. The two busiest
  addresses sent 10,069 and 5,406 requests over 2,000 distinct paths
  each; the top 404s are `/.env` in every spelling, `/.git/config`,
  `.aws`, `phpinfo.php`, `docker-compose.yml`.
- **20 % arrives through Cloudflare**, from 975 edge addresses, scanners
  included.
- **Fake crawlers.** All 1,050 requests with Googlebot's user agent came
  from five addresses with no reverse DNS.
- **A leak, in the log.** On 20 Sep at 00:31 and 01:52, `/.git/config`,
  `/.git/HEAD` and `/.git/logs/HEAD` were answered 200; from 04:38 on,
  404. `/README.md` is served too: the document root was a git checkout.

`data/me.conf` was built from the log: honey paths from the 404s most
addresses sent, checked against every path the site served; a 404 watch
with a ratio for the rest; the crawler list. Replayed:

| | Without the Cloudflare allowlist | `data/me.conf` |
|---|---|---|
| addresses banned | 400, **139 of them Cloudflare edges** | 261, all by honey |
| addresses that loaded the game, banned | | 0 |
| requests that XDP would have dropped | 84.5 % | 71.5 % |
| requests a banned scanner sent before its first ban | | median 3, at most 13 |

- **The allowlist is not optional** on a site behind a CDN (§8): without
  it, every visitor behind 139 edges would have been cut off.
- **Honey did the work.** The watch never fired: honey caught every
  scanner first.
- **One of the two `.git` leaks would have been stopped.** `80.94.95.211`
  was banned on its first request, 21 s before it fetched `.git`.
  `77.83.39.94` asked for `/.git/config` first: logban sees a request
  only after nginx answered it (§5.6). Keep secrets out of the document
  root, and `return 404` for `/.git` in nginx.

### 17.2 `clickHouse.access.log`

Generated sample data in nginx JSON (§4.2): 14,743 lines, each from a
different address, one host, evenly spread methods and user agents. It
checks JSON parsing at scale (every line parses; the reports equal those
of the same lines converted to `combined`) and that a log with one
request per address bans no one, clusters included.

### 17.3 `kaggle.access.log`

The Kaggle dataset "Web Server Access Logs": zanbil.ir, an e-commerce
site, 22 to 26 Jan 2019. 3.5 GB, 10,365,152 lines from 258,606
addresses, `combined` with a trailing `X-Forwarded-For`, no timing. Too
big for git: `.gitignore` keeps it out, and no test replays it.

- **Parsed whole**, at 87k lines/s; a full replay takes 4.5 minutes.
- **Mostly real users.** 92 % of answers are 200, 1 % are 404, and the
  most common 404s are harmless: AMP's
  `amp_preconnect_polyfill_404_or_other_error_expected` (5,917
  addresses) and iPhones' `apple-touch-icon*.png` (4,500).
- **The busiest clients are crawlers and staff.** Google's crawlers
  lead (one sent 353k requests and drew 10,865 404s). After them come
  the shop's own staff polling the admin panel (`/rapidGrails/jsonList`,
  `POST /orderAdministration/list`); one drew 11,165 500s.
- **Few attackers.** `/wp-login.php` from 119 addresses on a site that
  is not WordPress, and a product scraper on a hosting server
  (`91.99.72.15`: 38,694 requests, all product pages, no images or
  static files, a 2012 Chrome user agent).

Config: costly `^/(m/)?(filter|search|browse)(/|$)` and `^/(m/)?product/`,
honey for WordPress, `.env`, `.git` and phpMyAdmin paths, the 404 watch
with `ratio = 0.5`, crawlers `googlebot.com`, `google.com`,
`search.msn.com`, and the Cloudflare allowlist (some traffic came
through Cloudflare).

| | No DNS, no Cloudflare allowlist | Both |
|---|---|---|
| addresses banned | 154 | 142 |
| Googlebot, Bingbot or Cloudflare edges among them | 1 Googlebot (114 bans), 5 Bingbot, 6 edges | none |
| staff, or any address that loaded images or static files | 0 | 0 |
| requests inside ban windows | 1.09 % | 0.02 % |

With the defaults of §7.1 (a first ban of a minute, at most 15) instead
of 600 s and a day, the same 145 bans of the same 142 addresses; the
scraper's bans run 60, 120, 240 s instead of 600, 1200, 2400 s.

The 142: 140 scanners by honey, one path scanner by the 404 watch, and
the product scraper by the ratio rule. Staff were safe without any
exemption: the admin paths are not costly, so their share is 0.

Lessons: a crawler with a fast 404 rate needs the crawler check, which
needs DNS; a site behind a CDN needs its allowlist, as in §17.1; and the
crawler check needed the fixes of §6.3 to keep up.
