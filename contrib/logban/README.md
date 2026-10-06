# logban: ban CC attackers, scanners and brute-forcers by reading the nginx access log

Reads nginx's access log, finds the clients attacking the site, and drops
them at XDP with `drop <ip> ttl=<sec>`. No Lua needed. Python 3.8+,
standard library only.

Design, rules and trade-offs: [`doc/logban.md`](../../doc/logban.md).

| Attack | What gives it away | Config |
|---|---|---|
| [CC attack](#cc-attacks) (HTTP flood on expensive URLs) | nearly all its requests are costly, or it keeps backend workers busy | `costly`, `ratio`, `max_backend_seconds`, profiles, clusters, attack mode |
| [Scanning](#scanning) | probes for paths the site never serves; mostly 404s | `honey`, `watch scan` |
| [Password brute force](#password-brute-force) | many failed logins from one address | `watch login` |

Every rule is judged per address over a 60 s sliding window, every 10 s
(honey paths at once). A ban lasts 60 s and doubles for each repeat, up
to `max_ttl`: 15 minutes, so a mistake (a cleaned machine, a reassigned
address) costs little and a repeat offender is just banned again
([design §7.1](../../doc/logban.md#71-ttl)). A repeat is another ban of
the same address within `offense_memory` (a day) after its last ban
ended; a day without one and the next ban is 60 s again.

## CC attacks

The main job. A CC attack does not fill the NIC: a few hundred clients
loop on one expensive URL (a search, a report, a login page) and exhaust
the backend at a packet rate voidGate's flood policy never notices. A
browser that searches also loads pages, CSS, JS and images; a bot
flooding `/search` loads nothing else.

A request is **costly** if its path matches a `costly` regex. Find the
paths with `--top-paths` ([Tune, then enforce](#tune-then-enforce)). It
is the path, not the response time, so a backend slowed by the attack
does not make browsers' requests costly.

| Rule | Fires when |
|---|---|
| `ratio` | at least 100 costly requests, and at least 90 % of all its requests |
| `backend` | at least `max_backend_seconds` of backend time (off by default) |
| `cluster` | many addresses on one JA4 + user agent, nearly all costly: a wide, slow botnet (off by default, `cluster_min_addresses = 10`) |
| `throttled` (a watch) | nginx's `limit_req` already refused it 30 times: move it to XDP |

```
costly = ^/search
costly = ^/api/report
default.min_costly = 100         # profile "default": requests no
default.ratio = 0.9              # other profile matched
watch throttled = status:429     # set limit_req_status 429;
throttled.max = 30
```

**Apps and API clients** have a ratio near 1.0 by design. Give them a
profile with their own thresholds, chosen by user agent or path; keys
it does not set are `default`'s:

```
profile api = ua:^MyShop/
api.ratio = off
api.max_backend_seconds = 30     # half a backend worker per address
```

A forged user agent gets the same limits, not a pass. With a JA4 module,
log `ja4=$http_ssl_ja4` and match your app's TLS stacks instead, which a
script cannot fake with one header:

```
profile app = ja4:^t13d2014h2_a09f3c656075_14788d8d241b$
app.ratio = off
app.max_backend_seconds = 100
profile api_other = path:^/api/       # any other stack: strict
api_other.min_costly = 20
```

JA4 picks thresholds, never a pass: fingerprints change with OS updates
and can be copied ([design §5.5](../../doc/logban.md#55-ja4)).

**Under attack**, tighten the volume thresholds while the whole site is
loaded, and only then. The ratio is never scaled, so browsers still
pass ([design §5.9](../../doc/logban.md#59-attack-mode)):

```
attack_requests = 20000          # site requests per window; above
                                 # the "site peak" of --top-clients
default.attack_scale = 0.5       # min_costly 100 -> 50
```

## Scanning

Scanners probe for `.env`, `.git`, admin panels and old CMS paths. A
**honey path** is one the site never serves and no page links to: one
request bans at once, for 15 minutes:

```
honey = ^/(wp-login\.php|xmlrpc\.php|\.env|\.git(/|$))
honey = ^/(phpmyadmin|pma|adminer)
```

Never list a path a page links to, even hidden: prefetchers and mail
link scanners follow links. For the paths nobody listed, count 404s;
the ratio lets a NAT address with a few broken images pass:

```
watch scan = status:404
scan.max = 50
scan.ratio = 0.5                 # 404s must be half its requests
```

## Password brute force

One address trying many passwords on the login form:

```
watch login = method:POST path:^/login$ status:401|403
login.max = 20
login.ttl = 900                  # straight to the cap
```

This only works if the app answers a failed login with the status the
watch matches. Many answer 200 with an error page, or 302 back to the
form, the same as a success. Then count every POST to the form instead:
nobody submits it 20 times a minute, and the ratio lets an office
address, whose users also load pages, pass:

```
watch login = method:POST path:^/login$
login.max = 20
login.ratio = 0.5
```

**Not caught:** credential stuffing spread over many addresses, a few
attempts each, stays under any per-address count. That needs the app:
rate limits per account, or a challenge.

## Safe by default

A ban that hits a real visitor costs more than a bot that gets through
for another minute. logban is built so that one is rare and cheap:

- **Browsers pass the CC rules on their own traffic.** They load pages,
  CSS, JS and images, so their costly share stays far under 0.9, even
  behind a CGNAT or office address with hundreds of users. Attack mode
  never lowers that ratio.
- **Real search engine crawlers are not banned; fakes are.** List their
  domains (`logban.conf` has the usual five, commented out; the list is
  empty by default):

  ```
  crawler = googlebot.com
  crawler = search.msn.com
  ```

  An address whose user agent claims to be a crawler is checked by
  reverse DNS and then forward DNS, as the search engines document. A
  scraper copying Googlebot's user agent fails and is banned. The user
  agent alone never exempts anyone
  ([design §6.3](../../doc/logban.md#63-crawlers)).
- **Your own networks are never banned.** List monitoring, office egress
  and load balancers in `allow` (loopback always is), CDN ranges in an
  `allow_file`. voidGate refuses drops for its own `local_*` and
  `allow_*` networks too; logban then holds that address for the ban's
  ttl instead of asking every 10 s
  ([design §7.2](../../doc/logban.md#72-after-a-ban)).
- **A mistake costs a minute.** The first ban is 60 s, doubled only for a
  repeat within `offense_memory` (a day), and capped at 15 minutes.
- **Apps get their own limits, not a pass.** A profile gives your app's
  users thresholds that fit them; a bot forging the app's user agent or
  copying its TLS fingerprint meets the same limits
  ([CC attacks](#cc-attacks)).
- **You see it before it bans.** Replay, review and explain run on old
  logs and send nothing ([Tune, then enforce](#tune-then-enforce)).

## Log format

`combined` works. Add timing so logban can find costly paths itself:

```nginx
log_format logban '$remote_addr - $remote_user [$time_local] "$request" '
                  '$status $body_bytes_sent "$http_referer" '
                  '"$http_user_agent" rt=$request_time '
                  'urt=$upstream_response_time';
access_log /var/log/nginx/access.log logban;
```

The first field must be the TCP peer: with the realip module on, log
`$realip_remote_addr` there.

JSON logs (`log_format ... escape=json`) work too, line by line, with
nginx's field names (`remote_addr`, `time_local`, `request`, `status`,
`http_user_agent`, `request_time`, `upstream_response_time`). Other names:
the `json_*` keys in `logban.conf`
([design §4.2](../../doc/logban.md#42-json)).

## Tune, then enforce

Run each step on a normal week of logs (`.gz` and `-` for stdin work).
Nothing is sent to voidGate until step 5.

**1. What is costly?** The paths that cost the backend most: write the
`costly` regexes from them.

```sh
python3 logban.py -n --top-paths 20 -c logban.conf /var/log/nginx/access.log.*.gz
```

**2. What is normal?** Each client's peak backend seconds per window,
with percentiles per profile: choose `max_backend_seconds` above them.
The last line is the whole site's peak: set the attack mode thresholds
above it. `--top-ja4` lists the TLS stacks that call you, with profile
lines to uncomment for your app's; `--top-allowed` how much arrives
through the CDN, which only the CDN can stop.

```sh
python3 logban.py -n --top-clients 20 -c logban.conf /var/log/nginx/access.log.*.gz
python3 logban.py -n --top-ja4 20 -c logban.conf /var/log/nginx/access.log.*.gz
python3 logban.py -n --top-allowed 10 -c logban.conf /var/log/nginx/access.log.*.gz
```

**3. Who would be banned?** Replay as a dry run and review the list, one
row per address, most bans first. `--json` gives the same list, and any
`--top-*` report, to a program such as a web console; it can ban a row
with `voidgatectl drop <address> ttl=<ttl>`.

```sh
python3 logban.py -r -c logban.conf /var/log/nginx/access.log.*.gz
python3 logban.py -r --json --top-clients 20 -c logban.conf /var/log/nginx/access.log
```

**4. Why that one?** Every judgment of one address, with the thresholds
it was measured against: why it was banned, or why not.

```sh
python3 logban.py -c logban.conf -x 203.0.113.7 /var/log/nginx/access.log
```

**5. Live.** Dry first, then enforcing (root, or a member of voidGate's
`ctl_socket_group`). It follows the log like `tail -F`, through rotation
by rename or `copytruncate`, and picks up a changed `allow_file` within
one step.

```sh
python3 logban.py -n -f -c logban.conf /var/log/nginx/access.log
sudo python3 logban.py -f -c logban.conf /var/log/nginx/access.log
```

One line per ban:

```
2026-10-03T10:00:20Z ban 203.0.113.7 ttl=60 offense=1 total=100 costly=100 ratio=1.00 backend=10.0s rule=ratio
```

`logban.conf` documents every key: thresholds, `costly`, `profile`,
`honey`, `watch`, clusters, attack mode, `skip`, `allow`, `allow_file`,
`crawler`, ttl.

## Behind Cloudflare

Clients that come through the CDN cannot be banned at XDP; logban bans
the ones that hit the origin directly. Allowlist the CDN
([design §8](../../doc/logban.md#8-behind-a-cdn)):

```sh
sudo mkdir -p /etc/logban
sudo python3 cdn_allow.py cloudflare /etc/logban/cdn-allow.txt
# /etc/cron.d/logban-cdn
17 4 * * *  root  python3 /path/to/cdn_allow.py -q cloudflare /etc/logban/cdn-allow.txt
```

Add `allow_file = /etc/logban/cdn-allow.txt` to `logban.conf`. logban
picks up a new list within one step.

Put the same ranges in voidGate's `allow_networks`. The key replaces the
built-in list, so this keeps the built-ins (256 entries at most):

```sh
echo "allow_networks = 169.254.169.254/32, 127.0.0.0/8, ::1/128," \
     "fe80::/10, ff02::/16, $(grep -v '^#' /etc/logban/cdn-allow.txt |
     paste -sd, | sed 's/,/, /g')"
# paste the line into voidgate.conf, then: sudo voidgatectl reload
```

## Limits

- **Clients behind a CDN** cannot be banned at XDP: their packets come
  from the CDN's edges. Only the CDN can stop them.
- **Credential stuffing over many addresses**, a few attempts each, and
  **slow botnets that copy a common browser's TLS stack and user agent**
  pass every per-address rule. They need the app, `limit_req`, or a
  challenge page.
- **Not instant.** A ban comes up to one step (10 s) after the threshold,
  plus nginx's log buffering. Honey paths ban on the line itself.
- **One log, one machine.** No shared state between servers.
- **No memory across restarts.** Repeat-offense counts start over.
- **Follow mode prints no `--top-*` reports**; run them on a replay.
- **No systemd unit yet.** Run `-f` under your own supervisor.

Details and future work: [design §15](../../doc/logban.md#15-limits-and-future-work).

## Tests

```sh
python3 contrib/logban/test_logban.py      # also run by make test
sudo t/integration/logban.sh               # against a real daemon
```
