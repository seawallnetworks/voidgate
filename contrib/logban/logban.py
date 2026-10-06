#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0

"""Ban HTTP clients that spend their requests on costly URLs.

Reads an nginx access log (combined format, optionally with rt= and urt=
appended), scores every client address over a sliding window and pushes
`drop <ip> ttl=<sec>` to voidGate's control socket. --dry-run only prints.

A client is banned when, within the window and with the thresholds of
the profile its requests matched (default.* when none did):

    costly >= min_costly  and  costly / total >= ratio      (rule=ratio)
    backend seconds >= max_backend_seconds                   (rule=backend)

A request is costly when its path matches a `costly` regex. Browsers
also fetch pages and assets that are cheap, so their ratio stays low; a
bot hammering one expensive endpoint scores near 1.0.

See README.md next to this file.
"""

import argparse
import calendar
import collections
import gzip
import ipaddress
import json
import math
import os
import re
import signal
import socket
import sys
import threading
import time
from datetime import datetime


VG_SOCK_PATH = "/run/voidgate.sock"
MAX_TTL = 31536000


# $remote_addr - $remote_user [$time_local] "$request" $status
# $body_bytes_sent "$http_referer" "$http_user_agent" ...
# nginx escapes '"' inside variables as \x22, so [^"]* is safe.
LINE = re.compile(
    r'(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d{3}) \S+'
    r'(?: "[^"]*" "([^"]*)")?(.*)')
# $upstream_response_time has spaces between tries: "0.5, 0.2 : 0.1".
TIMING = re.compile(r'\b(rt|urt)=([-\d.,: ]+)')
NUMBER = re.compile(r'\d+(?:\.\d+)?')
# ja4=t13d1516h2_8daaf6152771_02713d6af862; "-" or empty when the
# connection had no TLS or the module did not run.
JA4 = re.compile(r'\bja4=([0-9a-z_]+)')
JA4_VALUE = re.compile(r'[0-9a-z_]+')
# Fields of a parsed line. A plain tuple: a namedtuple per line cost 20 %
# of a replay.
F_IP, F_T, F_PATH, F_COST, F_UA, F_JA4, F_METHOD, F_STATUS = range(8)


class ConfigError(Exception):
    pass


def warn(msg):
    sys.stderr.write("logban: %s\n" % msg)


def read_cidrs(path):
    """One CIDR (or bare address) per line; # comments."""

    nets = []

    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            line = line.split("#", 1)[0].strip()

            if not line:
                continue

            try:
                nets.append(ipaddress.ip_network(line, strict=False))

            except ValueError as e:
                raise ConfigError("%s:%d: %s" % (path, lineno, e))

    return nets


class AllowFiles:
    """allow_file lists, re-read when one of them changes. A cron job
    replaces them with mv, so a change is a new inode or mtime."""

    def __init__(self):
        self.paths = []
        self.stamps = None
        self.nets = []
        self.by_path = []           # (path, nets), for --top-allowed

    def stamp(self):
        out = []

        for path in self.paths:
            try:
                st = os.stat(path)
                out.append((st.st_ino, st.st_mtime_ns, st.st_size))

            except OSError:
                out.append(None)

        return out

    def load(self):
        """At startup: any error is fatal."""

        self.stamps = self.stamp()

        try:
            self.by_path = [(p, read_cidrs(p)) for p in self.paths]

        except OSError as e:
            raise ConfigError("allow_file: %s" % e)

        self.nets = [n for _, nets in self.by_path for n in nets]

    def refresh(self):
        """While running: True when the lists changed. A broken update
        keeps the old lists, and is retried only after the next change."""

        stamps = self.stamp()

        if stamps == self.stamps:
            return False

        self.stamps = stamps

        try:
            by_path = [(p, read_cidrs(p)) for p in self.paths]

        except (OSError, ConfigError) as e:
            warn("allow_file not reloaded, keeping %d networks: %s"
                 % (len(self.nets), e))
            return False

        self.by_path = by_path
        self.nets = [n for _, nets in by_path for n in nets]
        warn("allow_file reloaded: %d networks" % len(self.nets))
        return True


def parse_ratio(value):
    return None if value == "off" else float(value)


class Profile:
    """A set of thresholds, chosen per request by path, user agent or
    JA4. Index 0 is "default", for requests no profile matched; the
    others inherit the default.* keys they do not set."""

    KEYS = {
        "min_costly": int,
        "ratio": parse_ratio,
        "max_backend_seconds": float,
        "attack_scale": float,
    }
    # the default profile's keys when the config does not set them
    DEFAULTS = {
        "min_costly": 100,
        "ratio": 0.9,
        "max_backend_seconds": 0.0,
        # Attack mode scales min_costly and max_backend_seconds by
        # this; the ratio is not.
        "attack_scale": 0.5,
    }
    NAME = re.compile(r"[a-z][a-z0-9_]*")
    FIELDS = {"path": 0, "ua": 1, "ja4": 2}
    EXACT_JA4 = re.compile(r"\^([0-9a-z_]+)\$")

    def __init__(self, name):
        self.name = name
        self.prefix = "" if name == "default" else name + "."
        self.match = []             # (field index, regex), any one matches
        self.ja4 = set()            # ja4:^<fingerprint>$, matched as a set
        self.keys = {}              # KEYS this profile sets

    def add(self, field, rx):
        # An allowlist is dozens of exact fingerprints: one set lookup
        # instead of a regex each.
        m = self.EXACT_JA4.fullmatch(rx) if field == "ja4" else None

        if m:
            self.ja4.add(m.group(1))

        else:
            self.match.append((self.FIELDS[field], re.compile(rx)))

    def matches(self, values):
        """values: (path, user agent, ja4)"""

        return (values[2] in self.ja4
                or any(rx.search(values[i]) for i, rx in self.match))

    def limits(self, attack):
        """(min_costly, max_backend_seconds), scaled in attack mode. The
        ratio is never scaled: it is what lets browsers pass."""

        if attack:
            return (max(1, math.ceil(self.min_costly * self.attack_scale)),
                    self.max_backend_seconds * self.attack_scale)

        return self.min_costly, self.max_backend_seconds

    def rule(self, total, costly, cost, attack=False):
        """The rule this window's counts fire, or None."""

        min_costly, max_backend = self.limits(attack)

        if self.ratio is not None and costly >= min_costly \
                and costly >= self.ratio * total:
            return self.prefix + "ratio"

        if max_backend > 0 and cost >= max_backend:
            return self.prefix + "backend"

        return None

    def under(self, total, costly, cost, attack=False):
        """Why no rule fires, for --explain."""

        min_costly, max_backend = self.limits(attack)
        why = []

        if self.ratio is None:
            why.append("ratio off")

        elif costly < min_costly:
            why.append("costly %d < min_costly %d" % (costly, min_costly))

        else:
            why.append("costly share %.2f < ratio %.2f"
                       % (costly / total, self.ratio))

        if max_backend > 0:
            why.append("backend %.1f s < %.1f s" % (cost, max_backend))

        return "; ".join(why)


class Watch:
    """Count the requests that match all of a line's conditions, per
    address over the window; ban at max. Several lines with one name
    OR."""

    KEYS = {
        "max": int,
        "ratio": parse_ratio,
        "ttl": int,
    }
    # path is searched like costly; method and status must match whole
    FIELDS = {"method": F_METHOD, "path": F_PATH, "status": F_STATUS}

    def __init__(self, name):
        self.name = name
        self.alts = []              # [(field index, match)], all match
        self.keys = {}

    def add(self, value):
        conds = []

        for word in value.split():
            field, sep, rx = word.partition(":")

            if not sep or field not in self.FIELDS or not rx:
                raise ValueError("expected method:, path: or status:<regex>,"
                                 " got %r" % word)

            i = self.FIELDS[field]
            rx = re.compile(rx)
            conds.append((i, rx.search if i == F_PATH else rx.fullmatch))

        if not conds:
            raise ValueError("no condition")

        # Most lines fail the first test: the 3-digit status, then the
        # method, then the path.
        order = (F_STATUS, F_METHOD, F_PATH)
        conds.sort(key=lambda c: order.index(c[0]))
        self.alts.append(conds)

    def fires(self, hits, total):
        return hits >= self.max and (self.ratio is None
                                     or hits >= self.ratio * total)

    def matches(self, r):
        """r: a parse_line() tuple. Plain loops: this runs per line and
        watch, and any(all(...)) cost a third of a replay."""

        for conds in self.alts:
            for i, match in conds:
                if match(r[i]) is None:
                    break

            else:
                return True

        return False


class Config:

    # key: (type, default); list keys may repeat.
    SCALARS = {
        "window": (int, 60),
        "step": (int, 10),
        # A first ban is a minute: a false positive (a CGNAT address, a
        # browser near a threshold) costs one; a repeat offender doubles
        # up to max_ttl.
        "ttl": (int, 60),
        # One probe is the surest evidence: a honey ban starts at the
        # cap, and escalates from here if max_ttl is raised.
        "honey_ttl": (int, 900),
        # Every ban is capped here. Short, so a mistake costs little: a
        # cleaned machine, or the next user of a reassigned address, is
        # blocked at most 15 minutes; a repeat offender is re-banned at
        # its next offense (doc/logban.md section 7.1).
        "max_ttl": (int, 900),
        "offense_memory": (int, 86400),
        "cluster_min_addresses": (int, 0),
        "cluster_min_costly": (int, 300),
        "cluster_ratio": (float, 0.9),
        "cluster_member_min": (int, 3),
        # Attack mode: while the whole site's requests or backend seconds
        # in the window reach a threshold (0 = off), and attack_hold
        # seconds after, each profile's attack_scale applies.
        "attack_requests": (int, 0),
        "attack_backend_seconds": (float, 0.0),
        "attack_hold": (int, 300),
        # Only a client whose user agent claims to be a crawler gets the
        # DNS check, each lookup capped at crawler_timeout seconds.
        "crawler_ua": (str, r"(?i)bot|crawl|spider|slurp|google"),
        "crawler_timeout": (float, 1.0),
        "socket": (str, VG_SOCK_PATH),
        # JSON log lines: the field holding each value, first one present
        # wins. Defaults are nginx's variable names.
        "json_ip": (str, "remote_addr"),
        "json_time": (str, "time_local, time_iso8601, msec"),
        "json_request": (str, "request"),
        "json_method": (str, "request_method"),
        "json_uri": (str, "request_uri, uri"),
        "json_status": (str, "status"),
        "json_ua": (str, "http_user_agent"),
        "json_rt": (str, "request_time"),
        "json_urt": (str, "upstream_response_time"),
        "json_ja4": (str, "ja4, http_ssl_ja4"),
    }
    LISTS = ("costly", "skip", "honey", "allow", "allow_file", "crawler")
    NAMED = re.compile(r"(profile|watch)\s+(\S.*)")
    # rule names a watch would be confused with
    RESERVED = ("default", "ratio", "backend", "honey", "cluster")

    def __init__(self):
        for key, (_, default) in self.SCALARS.items():
            setattr(self, key, default)

        self.costly = []
        self.skip = []
        self.honey = []
        self.allow = [ipaddress.ip_network("127.0.0.0/8"),
                      ipaddress.ip_network("::1/128")]
        self.allow_files = AllowFiles()
        self.crawler = []
        self.profiles = [Profile("default")]
        self.watches = []
        self.pending = []           # (name, key, value) until check()

    def profile(self, name):
        for p in self.profiles:
            if p.name == name:
                return p

        return None

    def watch(self, name):
        for w in self.watches:
            if w.name == name:
                return w

        return None

    def load(self, path):
        with open(path) as f:
            for lineno, line in enumerate(f, 1):
                line = line.split("#", 1)[0].strip()

                if not line:
                    continue

                key, sep, value = line.partition("=")
                key, value = key.strip(), value.strip()

                if not sep or not value:
                    raise ConfigError("%s:%d: expected key = value"
                                      % (path, lineno))

                try:
                    self.set(key, value)

                except (ValueError, re.error) as e:
                    raise ConfigError("%s:%d: %s: %s"
                                      % (path, lineno, key, e))

        self.check()

    def set(self, key, value):
        # "profile <name>" and "watch <name>": any whitespace between
        m = self.NAMED.fullmatch(key)
        kind, name = m.groups() if m else ("", "")

        if key in self.SCALARS:
            setattr(self, key, self.SCALARS[key][0](value))

        elif key in ("costly", "skip", "honey"):
            getattr(self, key).append(re.compile(value))

        elif key == "allow":
            self.allow.append(ipaddress.ip_network(value, strict=False))

        elif key == "allow_file":
            self.allow_files.paths.append(value)

        elif key == "crawler":
            self.crawler.append("." + value.lstrip("."))

        elif kind == "profile":
            field, sep, rx = value.partition(":")

            if name == "default":
                raise ValueError("default is built in and matches what no"
                                 " profile did: set default.<key>")

            if not Profile.NAME.fullmatch(name):
                raise ValueError("bad profile name %r" % name)

            if not sep or field not in Profile.FIELDS or not rx:
                raise ValueError("expected path:, ua: or ja4:<regex>")

            p = self.profile(name)

            if p is None:
                p = Profile(name)
                self.profiles.append(p)

            p.add(field, rx)

        elif kind == "watch":
            if not Profile.NAME.fullmatch(name) or name in self.RESERVED:
                raise ValueError("bad watch name %r" % name)

            w = self.watch(name)

            if w is None:
                w = Watch(name)
                self.watches.append(w)

            w.add(value)

        elif "." in key and (key.split(".", 1)[1] in Profile.KEYS
                             or key.split(".", 1)[1] in Watch.KEYS):
            name, sub = key.split(".", 1)
            parse = Profile.KEYS.get(sub) or Watch.KEYS[sub]
            self.pending.append((name, sub, parse(value)))

        elif key in Profile.KEYS:
            raise ValueError("a profile key: write default.%s" % key)

        else:
            raise ValueError("unknown key")

    def check(self):
        self.allow_files.load()

        if self.step < 1 or self.window < self.step:
            raise ConfigError("need 1 <= step <= window")

        # ttl, honey_ttl and a watch's ttl may exceed max_ttl: capped at
        # it, with a warning (end of check()).
        if not 1 <= self.ttl or not 1 <= self.max_ttl <= MAX_TTL:
            raise ConfigError("need ttl >= 1 and 1 <= max_ttl <= %d"
                              % MAX_TTL)

        self.json_fields = json_fields(self)

        if self.cluster_min_addresses:
            if self.cluster_min_addresses < 2:
                raise ConfigError("cluster_min_addresses is 0 (off) or at"
                                  " least 2")

            if not 0 < self.cluster_ratio <= 1:
                raise ConfigError("cluster_ratio must be in (0, 1]")

            if self.cluster_min_costly < 1 or self.cluster_member_min < 1:
                raise ConfigError("cluster_min_costly and cluster_member_min"
                                  " must be at least 1")

        try:
            self.crawler_ua_rx = re.compile(self.crawler_ua)

        except re.error as e:
            raise ConfigError("crawler_ua: %s" % e)

        if self.crawler_timeout <= 0:
            raise ConfigError("crawler_timeout must be above 0")

        if min(self.attack_requests, self.attack_backend_seconds,
               self.attack_hold) < 0:
            raise ConfigError("attack_requests, attack_backend_seconds and"
                              " attack_hold must be at least 0")

        self.attack = (self.attack_requests > 0
                       or self.attack_backend_seconds > 0)

        if self.honey and self.honey_ttl < 1:
            raise ConfigError("need honey_ttl >= 1")

        # One hit bans: a pattern that matches the home page, or the empty
        # path of a malformed request line, would ban everyone.
        for rx in self.honey:
            for path in ("/", ""):
                if rx.search(path):
                    raise ConfigError("honey %r matches %r"
                                      % (rx.pattern, path or "an empty"
                                         " path"))

        for p in self.profiles[1:]:
            if self.watch(p.name):
                raise ConfigError("%s is both a profile and a watch"
                                  % p.name)

        for name, sub, value in self.pending:
            target = self.profile(name) or self.watch(name)

            if target is None:
                raise ConfigError("%s.%s: no profile or watch %s"
                                  % (name, sub, name))

            if sub not in target.KEYS:
                raise ConfigError("%s.%s: not a %s key" % (name, sub,
                                  type(target).__name__.lower()))

            target.keys[sub] = value

        for w in self.watches:
            w.max = w.keys.get("max")
            w.ratio = w.keys.get("ratio")
            w.ttl = w.keys.get("ttl", self.ttl)

            if w.max is None or w.max < 1:
                raise ConfigError("watch %s: %s.max must be set, at least 1"
                                  % (w.name, w.name))

            if w.ratio is not None and not 0 < w.ratio <= 1:
                raise ConfigError("%s.ratio must be in (0, 1] or off"
                                  % w.name)

            if w.ttl < 1:
                raise ConfigError("need %s.ttl >= 1" % w.name)

        ttls = [("ttl", self.ttl)]

        if self.honey:
            ttls.append(("honey_ttl", self.honey_ttl))

        ttls += [(w.name + ".ttl", w.keys["ttl"]) for w in self.watches
                 if "ttl" in w.keys]

        for name, ttl in ttls:
            if ttl > self.max_ttl:
                warn("%s %d is above max_ttl %d: capped at %d"
                     % (name, ttl, self.max_ttl, self.max_ttl))

        fires = []

        default = self.profiles[0]

        for p in self.profiles:
            for key in Profile.KEYS:
                inherit = (Profile.DEFAULTS[key] if p is default
                           else getattr(default, key))
                setattr(p, key, p.keys.get(key, inherit))

            if p.ratio is not None and not 0 < p.ratio <= 1:
                raise ConfigError("%s.ratio must be in (0, 1] or off"
                                  % p.name)

            if p.min_costly < 1:
                raise ConfigError("%s.min_costly must be at least 1"
                                  % p.name)

            if not 0 < p.attack_scale <= 1:
                raise ConfigError("%s.attack_scale must be in (0, 1]"
                                  % p.name)

            fire = ((p.ratio is not None and bool(self.costly))
                    or p.max_backend_seconds > 0)

            # A declared profile that judges nothing is a mistake; use
            # skip to not judge requests.
            if not fire and p.name != "default":
                raise ConfigError("profile %s: no rule can fire: ratio is"
                                  " off or nothing is costly, and"
                                  " max_backend_seconds is 0" % p.name)

            fires.append(fire)

        if not any(fires) and not self.watches and not self.honey:
            raise ConfigError("nothing is costly: set costly or"
                              " max_backend_seconds, or a watch or honey")


_time_cache = {}


MONTHS = {m: i for i, m in enumerate(calendar.month_abbr) if m}


def parse_time(s):
    """$time_local, "03/Oct/2026:10:00:00 +0000", as epoch seconds."""

    t = _time_cache.get(s)

    if t is None:
        if len(_time_cache) > 4096:
            _time_cache.clear()

        t = _time_cache[s] = parse_time_local(s)

    return t


def parse_time_local(s):
    # nginx's layout is fixed: slicing is 10x faster than strptime, which
    # ran for nearly every line of a log with few requests per second.
    try:
        if len(s) == 26 and s[2] == "/" and s[6] == "/" and s[11] == ":" \
                and s[20] == " " and s[21] in "+-":
            day, hour, minute, sec = (int(s[0:2]), int(s[12:14]),
                                      int(s[15:17]), int(s[18:20]))

            if 1 <= day <= 31 and hour < 24 and minute < 60 and sec < 61:
                offset = int(s[22:24]) * 3600 + int(s[24:26]) * 60

                return (calendar.timegm((int(s[7:11]), MONTHS[s[3:6]], day,
                                         hour, minute, sec))
                        - (offset if s[21] == "+" else -offset))

    except (KeyError, ValueError):
        pass

    # anything else: strptime decides, and raises ValueError if bad
    return datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z").timestamp()


def json_fields(cfg):
    """{json_<key> suffix: [field names]} from a Config's json_* keys."""

    fields = {}

    for key in JSON_KEYS:
        names = [n.strip() for n in getattr(cfg, "json_" + key).split(",")]

        if not all(names):
            raise ConfigError("json_%s: empty field name" % key)

        fields[key] = names

    return fields


JSON_KEYS = ("ip", "time", "request", "method", "uri", "status", "ua", "rt",
             "urt", "ja4")


def json_value(d, names):
    """The first of names present in d and not "-" or empty, as a
    string; "" when none is."""

    for name in names:
        v = d.get(name)

        if v is not None and v != "-" and v != "":
            return v if isinstance(v, str) else str(v)

    return ""


def json_time(d, names):
    for name in names:
        v = d.get(name)

        if v is None or v == "" or v == "-":
            continue

        if name == "msec" or isinstance(v, (int, float)):
            return float(v)

        if "/" in v:                        # $time_local
            return parse_time(v)

        t = _time_cache.get(v)              # $time_iso8601

        if t is None:
            if len(_time_cache) > 4096:
                _time_cache.clear()

            t = _time_cache[v] = datetime.fromisoformat(v).timestamp()

        return t

    raise ValueError("no time")


def seconds(*values):
    """Backend seconds from urt, else rt: "0.5", "-", a number, or one
    value per upstream tried ("0.5, 0.2 : 0.1"). None when absent."""

    for v in values:
        found = NUMBER.findall(v)

        if found:
            return sum(float(x) for x in found)

    return None


def parse_json(line, fields):
    """A JSON log line (log_format escape=json), as parse_line()."""

    try:
        d = json.loads(line)
        ip = json_value(d, fields["ip"])
        t = json_time(d, fields["time"])

    # not JSON, not an object, or a time field of the wrong type
    except (ValueError, TypeError, AttributeError):
        return None

    if not ip:
        return None

    parts = json_value(d, fields["request"]).split(" ")

    if len(parts) == 3:
        method, path = parts[0], parts[1].split("?", 1)[0]

    else:
        method = json_value(d, fields["method"])
        path = json_value(d, fields["uri"]).split("?", 1)[0]

    ja4 = json_value(d, fields["ja4"])

    return (ip, t, path,
            seconds(json_value(d, fields["urt"]), json_value(d, fields["rt"])),
            json_value(d, fields["ua"]),
            ja4 if JA4_VALUE.fullmatch(ja4) else "",
            method, json_value(d, fields["status"]))


def parse_line(line, fields=None):
    """Return (ip, epoch, path, cost, user agent, ja4, method, status):
    cost is backend seconds or None; user agent, ja4 and method are ""
    when absent. None when the line does not parse. A line starting with
    "{" is JSON, read with fields (json_fields(); nginx's names when
    None); any other line is combined."""

    if line[:1] == "{":
        return parse_json(line, fields or DEFAULT_JSON_FIELDS)

    m = LINE.match(line)

    if m is None:
        return None

    ip, stamp, request, status, ua, rest = m.groups()

    try:
        t = parse_time(stamp)

    except ValueError:
        return None

    parts = request.split(" ")

    if len(parts) == 3:
        method, path = parts[0], parts[1].split("?", 1)[0]

    else:
        method, path = "", ""

    timing = dict(TIMING.findall(rest))
    cost = seconds(timing.get("urt", ""), timing.get("rt", ""))

    ja4 = ""

    if "ja4=" in rest:
        m = JA4.search(rest)
        ja4 = m.group(1) if m else ""

    return ip, t, path, cost, ua or "", ja4, method, status


DEFAULT_JSON_FIELDS = json_fields(Config())


class Window:
    """Per (address, profile) [total, costly, backend seconds] over the
    last `buckets` steps, kept as running sums."""

    def __init__(self, step, buckets):
        self.step = step
        self.size = buckets
        self.buckets = collections.deque()
        self.totals = {}
        self.cur = None

    def add(self, key, costly, cost):
        for d in (self.buckets[-1], self.totals):
            s = d.get(key)

            if s is None:
                s = d[key] = [0, 0, 0.0]

            s[0] += 1
            s[1] += costly
            s[2] += cost

    def push(self):
        self.buckets.append({})

        if len(self.buckets) > self.size:
            for key, s in self.buckets.popleft().items():
                t = self.totals[key]

                if t[0] == s[0]:
                    del self.totals[key]
                    continue

                t[0] -= s[0]
                t[1] -= s[1]
                t[2] -= s[2]

    def reset(self):
        self.buckets.clear()
        self.totals.clear()
        self.buckets.append({})

    def remove(self, keys):
        for key in keys:
            self.totals.pop(key, None)

            for b in self.buckets:
                b.pop(key, None)


class Load:
    """The whole site's requests and backend seconds over the last
    `buckets` steps, moved with the Windows: attack mode reads it, and
    --top-clients its peak."""

    def __init__(self, buckets):
        self.size = buckets
        self.buckets = collections.deque()
        self.requests = 0
        self.cost = 0.0
        self.peak = [0, 0.0]        # requests, backend s, at any step

    def add(self, cost):
        b = self.buckets[-1]
        b[0] += 1
        b[1] += cost
        self.requests += 1
        self.cost += cost

    def push(self):
        self.buckets.append([0, 0.0])

        if len(self.buckets) > self.size:
            requests, cost = self.buckets.popleft()
            self.requests -= requests
            # no float drift left behind once the window is empty
            self.cost = self.cost - cost if self.requests else 0.0

    def reset(self):
        self.buckets.clear()
        self.buckets.append([0, 0.0])
        self.requests = 0
        self.cost = 0.0


def cluster_under(cfg, addresses, total, costly):
    """Why a fingerprint cluster does not fire, or "" when it does."""

    if addresses < cfg.cluster_min_addresses:
        return "addresses %d < cluster_min_addresses %d" % (
            addresses, cfg.cluster_min_addresses)

    if costly < cfg.cluster_min_costly:
        return "cluster costly %d < cluster_min_costly %d" % (
            costly, cfg.cluster_min_costly)

    if costly < cfg.cluster_ratio * total:
        return "cluster costly share %.2f < cluster_ratio %.2f" % (
            costly / total, cfg.cluster_ratio)

    return ""


def member_under(cfg, total, costly):
    """Why an address in a firing cluster is not banned, or "". A real
    user who shares the bots' fingerprint also loads cheap pages."""

    if costly < cfg.cluster_member_min:
        return "its costly %d < cluster_member_min %d" % (
            costly, cfg.cluster_member_min)

    if costly < cfg.cluster_ratio * total:
        return "its costly share %.2f < cluster_ratio %.2f" % (
            costly / total, cfg.cluster_ratio)

    return ""


def clock_str(t):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(t))


class Explain:
    """--explain: every judgment of one address, with the thresholds it
    was measured against, its honey hits and bans, then a summary."""

    def __init__(self, ip, judge, out):
        self.ip = ip
        self.judge = judge
        self.cfg = judge.cfg
        self.out = out
        self.lines = 0
        self.skipped = 0
        self.judged = collections.Counter()     # profile index -> lines
        self.honeys = 0
        self.why_listed = None
        self.bans = []
        self.peaks = {}                         # profile index -> counts
        self.held = []                          # steps while banned
        out.write("explain %s: %d s window, judged every %d s; times are"
                  " window ends, UTC\n" % (ip, self.cfg.window,
                                            self.cfg.step))

    def row(self, t, what, text):
        self.out.write("%s  %-12s %s\n" % (clock_str(t), what, text))

    LISTED = {"allow": "allowlisted (allow or allow_file)",
              "bad-address": "not an IP address"}

    def listed(self, t, why):
        if self.why_listed is None:
            self.why_listed = why
            self.row(t, "never judged", "%s: no rule, watch or ban applies"
                     % self.LISTED.get(why, why))

    def flush_held(self):
        """One line for the steps judged while banned. In a replay the
        client keeps sending; live, XDP drops it and they never come."""

        if self.held:
            self.row(self.held[-1], "banned", "%d steps not shown: the"
                     " replay keeps its requests, XDP would drop them"
                     % len(self.held))
            self.held = []

    def honey(self, t, path):
        self.honeys += 1
        self.flush_held()
        self.row(t, "honey", path)

    def ban(self, t, rule, ttl, offense, err):
        self.flush_held()

        if err:
            self.row(t, "ban failed", "rule=%s ttl=%d error=%s"
                     % (rule, ttl, err))
            return

        self.bans.append((t, rule, ttl))
        self.row(t, "BAN", "rule=%s ttl=%d offense=%d, until %s"
                 % (rule, ttl, offense, clock_str(t + ttl)))

    def verdict(self, now, rule):
        # step() returns early while the address is banned
        why = self.judge.exempt.reason(self.ip)

        if why:
            return "fires %s, exempt: %s" % (rule, why)

        return "fires %s" % rule

    def step(self, now):
        cfg = self.cfg
        win = self.judge.win
        all_req = 0

        if self.judge.banned.get(self.ip, 0) > now:
            if any((self.ip, i) in win.totals
                   for i in range(len(cfg.profiles))):
                self.held.append(now)
            return

        self.flush_held()

        for pi, p in enumerate(cfg.profiles):
            st = win.totals.get((self.ip, pi))

            if st is None:
                continue

            total, costly, cost = st
            all_req += total
            pk = self.peaks.setdefault(pi, [0, 0, 0.0])
            pk[:] = [max(pk[0], total), max(pk[1], costly),
                     max(pk[2], cost)]
            attack = self.judge.attack
            rule = p.rule(total, costly, cost, attack)
            self.row(now, p.name, "total=%d costly=%d backend=%.1fs  %s"
                     % (total, costly, cost,
                        self.verdict(now, rule) if rule
                        else "under: " + p.under(total, costly, cost,
                                                 attack)))

        for wi, w in enumerate(cfg.watches):
            st = self.judge.watched.totals.get((self.ip, wi))

            if st is None:
                continue

            hits = st[0]
            total = all_req or hits

            if w.fires(hits, total):
                text = self.verdict(now, w.name)

            elif hits < w.max:
                text = "under: hits %d < max %d" % (hits, w.max)

            else:
                text = "under: hits share %.2f < ratio %.2f" % (
                    hits / total, w.ratio)

            self.row(now, "watch " + w.name, "hits=%d of %d  %s"
                     % (hits, total, text))

        if self.judge.clusters is not None:
            for (ja4, ua, ip), (total, costly, _) in \
                    self.judge.clusters.totals.items():
                if ip != self.ip:
                    continue

                n, ctotal, ccostly = self.judge.cluster_agg[(ja4, ua)]
                why = (cluster_under(cfg, n, ctotal, ccostly)
                       or member_under(cfg, total, costly))
                self.row(now, "cluster", "addresses=%d costly=%d/%d, its"
                         " %d/%d  %s"
                         % (n, ccostly, ctotal, costly, total,
                            "under: " + why if why
                            else self.verdict(now, "cluster")))

    def summary(self):
        out = self.out
        cfg = self.cfg
        self.flush_held()

        if not self.lines:
            out.write("\n%s is not in the log. nginx writes IPv6 compressed"
                      " and lowercase; behind [::] without ipv6only, IPv4"
                      " clients are ::ffff:a.b.c.d.\n" % self.ip)
            return

        judged = ", ".join("%s %d" % (cfg.profiles[pi].name, n)
                           for pi, n in sorted(self.judged.items()))
        out.write("\nsummary: %d lines: judged %s; skipped %d; honey %d"
                  % (self.lines, judged or "0", self.skipped, self.honeys))

        if self.why_listed:
            out.write("; never judged: %s" % self.why_listed)

        out.write("\n")

        for pi, (total, costly, cost) in sorted(self.peaks.items()):
            out.write("peak window, %s: total %d, costly %d, backend %.1f s"
                      "\n" % (cfg.profiles[pi].name, total, costly, cost))

        if self.bans:
            out.write("bans: %s\n" % ", ".join(
                "%s at %s, ttl %d" % (rule, clock_str(t), ttl)
                for t, rule, ttl in self.bans))

        else:
            out.write("bans: none\n")


class Exempt:
    """Who a rule may not ban: allowlisted addresses, and crawlers whose
    reverse DNS checks out. Every answer is cached per address."""

    def __init__(self, cfg, resolve, verbose=0):
        self.cfg = cfg
        self.resolve = resolve
        self.verbose = verbose
        self.listed = {}            # ip -> "allow", "bad-address" or ""
        self.sources = {}           # ip -> its allowlist, or "" (cache)
        self.crawlers = {}          # ip -> verified crawler (DNS cache)
        self.claims = set()         # ips whose user agent claimed a crawler
        self.claim_ua = {}          # user agent -> claims (cache)
        self.dns_timeouts = 0

    def refresh(self):
        """Reload changed allow_files, and forget what they answered."""

        if self.cfg.allow_files.refresh():
            self.listed.clear()
            self.sources.clear()

    def allowed_source(self, ip):
        """The allowlist an address is on: "allow" (the allow keys,
        loopback included), "allow_file <path>", or ""."""

        src = self.sources.get(ip)

        if src is not None:
            return src

        src = ""

        try:
            addr = ipaddress.ip_address(ip)

        except ValueError:
            addr = None

        if addr is not None:
            if any(addr in net for net in self.cfg.allow):
                src = "allow"

            else:
                for path, nets in self.cfg.allow_files.by_path:
                    if any(addr in net for net in nets):
                        src = "allow_file " + path
                        break

        if len(self.sources) > 65536:
            self.sources.clear()

        self.sources[ip] = src
        return src

    def listed_reason(self, ip):
        """Why an address is never judged, or "". Cached: this runs for
        every line, the allowlists only once per address."""

        why = self.listed.get(ip)

        if why is not None:
            return why

        try:
            addr = ipaddress.ip_address(ip)

        except ValueError:
            why = "bad-address"

        else:
            nets = self.cfg.allow + self.cfg.allow_files.nets
            why = "allow" if any(addr in net for net in nets) else ""

        if len(self.listed) > 65536:
            self.listed.clear()

        self.listed[ip] = why
        return why

    def claim(self, ip, ua):
        """Remember an address that sent a crawler's user agent. Only
        those get the DNS check: a scanner with a browser's user agent is
        banned without a lookup, so a reverse zone that never answers
        cannot stall the loop for it."""

        c = self.claim_ua.get(ua)

        if c is None:
            if len(self.claim_ua) > 65536:
                self.claim_ua.clear()

            c = self.claim_ua[ua] = bool(self.cfg.crawler_ua_rx.search(ua))

        if c and ip not in self.claims:
            if len(self.claims) > 65536:
                self.claims.clear()

            self.claims.add(ip)

    def reason(self, ip):
        """Checked only for an address that matched a rule. Counts made
        before an allow_file reload are still excused; the DNS crawler
        check is too slow to run per line, and runs only for an address
        that claimed to be a crawler."""

        why = self.listed_reason(ip)

        if why or not self.cfg.crawler or ip not in self.claims:
            return why

        crawler = self.crawlers.get(ip)

        if crawler is None:
            crawler = self.is_crawler(ip)

            if len(self.crawlers) > 65536:
                self.crawlers.clear()

            self.crawlers[ip] = crawler

        return "crawler" if crawler else ""

    def is_crawler(self, ip):
        """Reverse DNS ends in a crawler domain, and that name resolves
        back to ip. The user agent is not trusted."""

        names, _ = self.lookup(ip)

        for name in names:
            if name.lower().endswith(tuple(self.cfg.crawler)):
                _, back = self.lookup(name)

                if ip in back:
                    return True

        return False

    def lookup(self, name):
        """self.resolve(name), given crawler_timeout seconds. A lookup
        that does not answer in time is "not a crawler"; its thread is
        left to finish on its own."""

        out = []
        t = threading.Thread(target=lambda: out.append(self.resolve(name)),
                             daemon=True)
        t.start()
        t.join(self.cfg.crawler_timeout)

        if out:
            return out[0]

        self.dns_timeouts += 1

        if self.verbose:
            warn("crawler check: %s timed out after %.1f s"
                 % (name, self.cfg.crawler_timeout))

        return [], set()


class Judge:

    def __init__(self, cfg, act, out=sys.stdout, verbose=0,
                 resolve=None):
        self.cfg = cfg
        self.act = act
        self.out = out
        self.verbose = verbose
        self.exempt = Exempt(cfg, resolve or resolve_dns, verbose)
        self.win = Window(cfg.step, cfg.window // cfg.step)
        # (address, watch) -> [hits, 0, 0], moved with self.win
        self.watched = Window(cfg.step, cfg.window // cfg.step)
        # (ja4, user agent, address) -> [total, costly, backend s], for
        # the profiles with the ratio rule on; None when clusters are off
        self.clusters = (Window(cfg.step, cfg.window // cfg.step)
                         if cfg.cluster_min_addresses else None)
        self.cluster_agg = {}       # (ja4, ua) -> [addresses, total, costly]
        # site-wide load; None unless attack mode is on (or --top-clients)
        self.load = Load(cfg.window // cfg.step) if cfg.attack else None
        self.attack = False         # attack mode now
        self.attack_until = 0       # its hold ends
        self.banned = {}            # ip -> until
        self.offenses = {}          # ip -> (count, when its ban ended)
        self.paths = {}             # path -> [count, backend seconds]
        self.timed = False
        self.lines = 0
        self.skipped = 0
        self.unjudged = 0
        self.honey_hits = 0
        self.history = None         # list: keep every ban (--review)
        self.traffic = None         # ip -> [requests, costly, backend s]
                                    # over the whole log (--review)
        self.peaks = None           # dict: per-client peaks (--top-clients)
        self.ja4s = None            # dict: per-JA4 totals (--top-ja4)
        self.allowed = None         # dict: allowlisted traffic (--top-allowed)
        self.explain = None         # Explain: one address (--explain)

    def feed(self, line):
        r = parse_line(line, self.cfg.json_fields)

        if r is None:
            self.skipped += 1
            return

        ip, t, path, cost, ua, ja4, _, _ = r
        self.lines += 1

        if self.traffic is not None:
            tr = self.traffic.get(ip)

            if tr is None:
                tr = self.traffic[ip] = [0, 0, 0.0]

            tr[0] += 1
            tr[1] += self.is_costly(path)
            tr[2] += cost or 0.0
        self.clock(t)
        x = self.explain if self.explain and ip == self.explain.ip else None

        # Everything that reaches the backend, allowlisted and skipped
        # included; not a banned client: live, XDP drops it.
        if self.load is not None and self.banned.get(ip, 0) <= t:
            self.load.add(cost or 0.0)

        if x:
            x.lines += 1

        if self.cfg.crawler:
            self.exempt.claim(ip, ua)

        if self.allowed is not None:
            self.count_allowed(ip, path, cost)

        # A path no real client asks for: ban on the first hit, now, not
        # at the next step. Before skip, so skip cannot hide a probe.
        if self.cfg.honey and any(rx.search(path) for rx in self.cfg.honey):
            self.honey(ip, t, path)
            return

        if any(p.search(path) for p in self.cfg.skip):
            if x:
                x.skipped += 1
            return

        if cost is not None:
            self.timed = True

        p = self.paths.get(path)

        if p is None:
            p = self.paths[path] = [0, 0.0]

        p[0] += 1
        p[1] += cost or 0.0

        # An allowed address (a CDN edge) can never be banned: keep it in
        # the path report above, but out of the window.
        if self.exempt.listed_reason(ip):
            self.unjudged += 1

            if x:
                x.listed(t, self.exempt.listed_reason(ip))
            return

        costly = self.is_costly(path)

        key = (ip, self.profile_of((path, ua, ja4))
                   if len(self.cfg.profiles) > 1 else 0)
        self.win.add(key, int(costly), cost or 0.0)

        # An app's API profile has ratio off: its users, all costly by
        # design, must not form a cluster.
        if self.clusters is not None \
                and self.cfg.profiles[key[1]].ratio is not None:
            self.clusters.add((ja4, ua, ip), int(costly), cost or 0.0)

        if x:
            x.judged[key[1]] += 1

        if self.cfg.watches:
            for i, w in enumerate(self.cfg.watches):
                if w.matches(r):
                    self.watched.add((ip, i), 0, 0.0)

        if self.peaks is not None:
            pk = self.peaks.get(key)

            if pk is None:
                # peak backend s, peak requests, peak costly, all requests
                pk = self.peaks[key] = [0.0, 0, 0, 0]

            pk[3] += 1

        if self.ja4s is not None:
            j = self.ja4s.get(ja4)

            if j is None:
                # requests, backend s, addresses, user agents
                j = self.ja4s[ja4] = [0, 0.0, set(), collections.Counter()]

            j[0] += 1
            j[1] += cost or 0.0
            j[2].add(ip)
            j[3][ua] += 1

    def profile_of(self, values):
        """Index of the first profile that matches (path, user agent,
        ja4), 0 for default."""

        profiles = self.cfg.profiles

        for i in range(1, len(profiles)):
            if profiles[i].matches(values):
                return i

        return 0

    def clock(self, t):
        """Move the window to time t. A late line (nginx logs a request
        when it ends) is counted in the current bucket."""

        idx = int(t // self.cfg.step)
        win = self.win

        if win.cur is None:
            win.cur = idx

            for w in self.windows():
                w.reset()
            return

        if idx <= win.cur:
            return

        if idx - win.cur > win.size:
            # A gap longer than the window: judge once, start over.
            self.judge((win.cur + 1) * self.cfg.step)

            for w in self.windows():
                w.reset()
            win.cur = idx
            return

        while win.cur < idx:
            win.cur += 1
            self.judge(win.cur * self.cfg.step)

            for w in self.windows():
                w.push()

    def windows(self):
        """Everything that moves with the clock."""

        return [w for w in (self.win, self.watched, self.clusters,
                            self.load) if w is not None]

    def finish(self):
        """Judge the partial window at end of input."""

        if self.win.cur is not None:
            self.judge((self.win.cur + 1) * self.cfg.step)

    def judge(self, now):
        cfg = self.cfg

        self.exempt.refresh()

        if self.clusters is not None:
            agg = self.cluster_agg = {}

            for (ja4, ua, _), (total, costly, _) in \
                    self.clusters.totals.items():
                a = agg.get((ja4, ua))

                if a is None:
                    a = agg[(ja4, ua)] = [0, 0, 0]

                a[0] += 1
                a[1] += total
                a[2] += costly

        if self.load is not None:
            self.judge_load(now)

        if self.explain:
            self.explain.step(now)

        for key, (total, costly, cost) in list(self.win.totals.items()):
            ip, pi = key
            p = cfg.profiles[pi]

            if self.peaks is not None:
                pk = self.peaks[key]
                pk[0] = max(pk[0], cost)
                pk[1] = max(pk[1], total)
                pk[2] = max(pk[2], costly)

            rule = p.rule(total, costly, cost, self.attack)

            if rule is None:
                continue

            if self.banned.get(ip, 0) > now:
                continue

            why = self.exempt.reason(ip)

            if why:
                if self.verbose:
                    self.log("skip %s %s total=%d costly=%d"
                             % (ip, why, total, costly))
                continue

            # Tagged when only the tighter thresholds fired, so a review
            # can tell attack mode's bans from the rest.
            self.ban(ip, now, rule, total, costly, cost,
                     note=" mode=attack" if self.attack
                     and p.rule(total, costly, cost) is None else "")

        if self.watched.totals:
            self.judge_watches(now)

        if self.cluster_agg:
            self.judge_clusters(now)

    def judge_load(self, now):
        """Attack mode: on while the site's load in the window is at an
        attack_ threshold, and for attack_hold seconds after. The hold
        keeps it on while its own bans bring the load down."""

        cfg = self.cfg
        load = self.load
        load.peak[0] = max(load.peak[0], load.requests)
        load.peak[1] = max(load.peak[1], load.cost)

        if not cfg.attack:
            return

        over = (0 < cfg.attack_requests <= load.requests
                or 0 < cfg.attack_backend_seconds <= load.cost)

        if over:
            self.attack_until = now + cfg.attack_hold

        on = over or now < self.attack_until

        if on == self.attack:
            return

        self.attack = on
        text = "%s requests=%d backend=%.1fs" % ("on" if on else "off",
                                                 load.requests, load.cost)
        self.out.write("%s attack %s\n" % (iso(now), text))
        self.out.flush()

        if self.explain:
            self.explain.row(now, "attack", text)

    def judge_clusters(self, now):
        """Many addresses, each under every per-address threshold, with
        one fingerprint and nearly only costly requests: a wide, slow
        botnet. Ban the members that behave like it."""

        cfg = self.cfg
        hot = {k: a for k, a in self.cluster_agg.items()
               if not cluster_under(cfg, *a)}

        if not hot:
            return

        for (ja4, ua, ip), (total, costly, cost) in \
                list(self.clusters.totals.items()):
            a = hot.get((ja4, ua))

            if a is None or member_under(cfg, total, costly):
                continue

            if self.banned.get(ip, 0) > now:
                continue

            why = self.exempt.reason(ip)

            if why:
                if self.verbose:
                    self.log("skip %s %s cluster" % (ip, why))
                continue

            self.ban(ip, now, "cluster", total, costly, cost,
                     note=' cluster=%d%s ua="%s"'
                     % (a[0], " ja4=" + ja4 if ja4 else "", ua[:60]))

    def judge_watches(self, now):
        cfg = self.cfg
        totals = None

        for (ip, wi), (hits, _, _) in list(self.watched.totals.items()):
            w = cfg.watches[wi]

            if hits < w.max:
                continue

            if totals is None:
                # all of each address's requests in the window, for ratio
                totals = collections.Counter()

                for (addr, _), st in self.win.totals.items():
                    totals[addr] += st[0]

            total = totals[ip] or hits

            if not w.fires(hits, total):
                continue

            if self.banned.get(ip, 0) > now:
                continue

            why = self.exempt.reason(ip)

            if why:
                if self.verbose:
                    self.log("skip %s %s %s hits=%d" % (ip, why, w.name,
                                                        hits))
                continue

            self.ban(ip, now, w.name, total, 0, 0.0, base=w.ttl,
                     note=" hits=%d" % hits)

    def honey(self, ip, now, path):
        self.honey_hits += 1
        x = self.explain if self.explain and ip == self.explain.ip else None

        if x:
            x.honey(now, path)

        if self.banned.get(ip, 0) > now:
            return

        why = self.exempt.reason(ip)

        if why:
            if self.verbose:
                self.log("skip %s %s honey %s" % (ip, why, path))
            return

        # A failed ban is retried by the scanner's next probe.
        self.ban(ip, now, "honey", 1, 0, 0.0, base=self.cfg.honey_ttl,
                 note=" path=" + path)

    def ban(self, ip, now, rule, total, costly, cost, base=None, note=""):
        cfg = self.cfg
        count, ended = self.offenses.get(ip, (0, 0))

        # Forgotten once quiet for offense_memory after the last ban
        # ended. Counted from its start, a ban of max_ttl (a day, like
        # offense_memory) could never be followed by a repeat in time,
        # and the most persistent clients fell back to the first ttl.
        if now - ended > cfg.offense_memory:
            count = 0

        ttl = min((base or cfg.ttl) << min(count, 30), cfg.max_ttl)
        err = self.act(ip, ttl)
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

        held = isinstance(err, Refused)

        if self.explain and ip == self.explain.ip:
            self.explain.ban(now, rule, ttl, count + 1, err)

        self.out.write("%s ban %s ttl=%d offense=%d total=%d costly=%d"
                       " ratio=%.2f backend=%.1fs rule=%s%s%s%s\n"
                       % (stamp, ip, ttl, count + 1, total, costly,
                          costly / total, cost, rule, note,
                          " error=" + err if err else "",
                          " retry_after=%ds" % ttl if held else ""))
        self.out.flush()

        if err and not held:
            return              # socket error: retried at the next step

        if not err:
            self.offenses[ip] = (count + 1, now + ttl)

            if self.history is not None:
                self.history.append((now, ip, ttl, total, costly, cost,
                                     rule, note.strip()))

        # Banned, or refused: either way not judged again for ttl.
        self.banned[ip] = now + ttl

        self.win.remove([(ip, i) for i in range(len(cfg.profiles))])
        self.watched.remove([(ip, i) for i in range(len(cfg.watches))])

        if len(self.banned) > 65536:
            self.banned = {k: v for k, v in self.banned.items() if v > now}

    def is_costly(self, path):
        return any(p.search(path) for p in self.cfg.costly)

    def count_allowed(self, ip, path, cost):
        """--top-allowed: every line from an allowlisted address, a CDN
        edge say, honey probes and skipped paths included."""

        self.allowed["lines"] += 1
        src = self.exempt.allowed_source(ip)

        if not src:
            return

        costly = int(self.is_costly(path))
        st = self.allowed["sources"].get(src)

        if st is None:
            st = self.allowed["sources"][src] = [0, 0, 0.0, set()]

        st[0] += 1
        st[1] += costly
        st[2] += cost or 0.0
        st[3].add(ip)
        a = self.allowed["ips"].get(ip)

        if a is None:
            a = self.allowed["ips"][ip] = [src, 0, 0]

        a[1] += 1
        a[2] += costly

    def log(self, msg):
        warn(msg)


# --top-* reports: data first (for --json), then text from the data.



def top_paths(judge, n):
    """The paths that cost the backend most (or the most requested
    ones when the log has no timing)."""

    key = (lambda kv: kv[1][1]) if judge.timed else (lambda kv: kv[1][0])
    top = sorted(judge.paths.items(), key=key, reverse=True)[:n]

    return {"by": "backend_seconds" if judge.timed else "requests",
            "paths": [{"path": path, "requests": count,
                       "backend_seconds": cost}
                      for path, (count, cost) in top]}


def top_clients(judge, n):
    """The clients with the highest peak backend seconds in one
    window, and percentiles over those this run did not ban: the
    numbers to choose max_backend_seconds from."""

    col = 0 if judge.timed else 1
    rows = sorted(judge.peaks.items(), key=lambda kv: (-kv[1][col], kv[0]))
    names = [p.name for p in judge.cfg.profiles]

    def rank(kept, q):
        # nearest rank
        return kept[max(0, math.ceil(len(kept) * q / 100) - 1)]

    percentiles = {}

    for pi, name in enumerate(names):
        kept = sorted(pk[col] for (ip, i), pk in rows
                      if i == pi and ip not in judge.offenses)

        if kept:
            percentiles[name] = dict(
                [("clients", len(kept))]
                + [(label, rank(kept, q)) for label, q in
                   (("p50", 50), ("p90", 90), ("p99", 99),
                    ("p99.9", 99.9), ("max", 100))])

    return {"by": "backend_seconds" if judge.timed else "requests",
            "window": judge.cfg.window,
            "clients": [{"address": ip, "profile": names[pi],
                         "backend_seconds": pk[0],
                         "workers": pk[0] / judge.cfg.window,
                         "requests": pk[1], "costly": pk[2],
                         "all_requests": pk[3],
                         "banned": ip in judge.offenses}
                        for (ip, pi), pk in rows[:n]],
            "percentiles": percentiles,
            # the attack_ thresholds go above a normal week's peak
            "site": {"requests": judge.load.peak[0],
                     "backend_seconds": judge.load.peak[1]}
            if judge.load else None}


def top_ja4(judge, n):
    """The JA4 fingerprints by requests, with the user agent each
    one sends most. "" is requests without a fingerprint."""

    rows = sorted(judge.ja4s.items(), key=lambda kv: (-kv[1][0], kv[0]))
    all_req = sum(j[0] for _, j in rows) or 1
    out = []

    for ja4, (req, cost, addrs, uas) in rows[:n]:
        ua, count = uas.most_common(1)[0]
        out.append({"ja4": ja4, "requests": req, "share": req / all_req,
                    "addresses": len(addrs),
                    "banned": len(addrs & judge.offenses.keys()),
                    "backend_seconds": cost, "top_user_agent": ua,
                    "top_user_agent_requests": count})

    return {"fingerprints": out}


def top_allowed(judge, n):
    """Allowlisted traffic, per allowlist, and its busiest
    addresses: how much reaches the origin through a CDN."""

    lines = judge.allowed["lines"] or 1
    ips = sorted(judge.allowed["ips"].items(),
                 key=lambda kv: (-kv[1][1], kv[0]))

    return {"lines": judge.allowed["lines"],
            "sources": [{"source": src, "requests": st[0],
                         "share": st[0] / lines, "addresses": len(st[3]),
                         "costly": st[1], "backend_seconds": st[2]}
                        for src, st in sorted(
                            judge.allowed["sources"].items(),
                            key=lambda kv: -kv[1][0])],
            "addresses": [{"address": ip, "source": a[0],
                           "requests": a[1], "costly": a[2]}
                          for ip, a in ips[:n]]}


def report_allowed(judge, n, out=None):
    out = out or judge.out
    data = top_allowed(judge, n)
    total = sum(s["requests"] for s in data["sources"])

    out.write("\nallowlisted traffic, not judged: %d of %d lines, %.1f%%"
              "\n" % (total, data["lines"],
                      total * 100 / (data["lines"] or 1)))

    if not data["sources"]:
        return

    width = max(len(s["source"]) for s in data["sources"])
    out.write("%-*s %9s %6s %9s %8s %10s\n"
              % (width, "source", "requests", "share", "addresses",
                 "costly", "backend_s"))

    for s in data["sources"]:
        out.write("%-*s %9d %5.1f%% %9d %8d %10.1f\n"
                  % (width, s["source"], s["requests"], s["share"] * 100,
                     s["addresses"], s["costly"], s["backend_seconds"]))

    width = max(len(a["address"]) for a in data["addresses"])
    out.write("\n%3s  %-*s %9s %8s  %s\n"
              % ("#", width, "address", "requests", "costly", "source"))

    for i, a in enumerate(data["addresses"], 1):
        out.write("%3d  %-*s %9d %8d  %s\n"
                  % (i, width, a["address"], a["requests"], a["costly"],
                     a["source"]))


def report_paths(judge, n, out=None):
    out = out or judge.out
    data = top_paths(judge, n)

    out.write("\n%-10s %-12s %-9s path\n"
              % ("requests", "backend_s", "avg_ms"))

    for p in data["paths"]:
        out.write("%-10d %-12.1f %-9.1f %s\n"
                  % (p["requests"], p["backend_seconds"],
                     p["backend_seconds"] * 1000 / p["requests"],
                     p["path"]))

    if not judge.timed:
        out.write("(no rt=/urt= in the log: sorted by requests)\n")


def report_clients(judge, n, out=None):
    out = out or judge.out
    data = top_clients(judge, n)
    rows = data["clients"]
    names = [p.name for p in judge.cfg.profiles]
    pw = max(len(n) for n in names)

    out.write("\nclients by peak %s in one %d s window"
              " (allowlisted addresses are not judged, so not shown)\n"
              % ("backend seconds" if judge.timed else "requests",
                 judge.cfg.window))

    if rows:
        width = max(len(r["address"]) for r in rows)
        out.write("%3s  %-*s  %-*s %10s %8s %8s %8s %9s  %s\n"
                  % ("#", width, "address", pw, "profile", "backend_s",
                     "workers", "requests", "costly", "all_req",
                     "banned"))

    for i, r in enumerate(rows, 1):
        out.write("%3d  %-*s  %-*s %10.1f %8.2f %8d %8d %9d  %s\n"
                  % (i, width, r["address"], pw, r["profile"],
                     r["backend_seconds"], r["workers"], r["requests"],
                     r["costly"], r["all_requests"],
                     "yes" if r["banned"] else ""))

    out.write("\npeak %s per window, clients not banned:\n"
              % ("backend s" if judge.timed else "requests"))

    for name in names:
        p = data["percentiles"].get(name)

        if p:
            out.write("  %-*s %7d clients  p50 %.1f  p90 %.1f  p99 %.1f"
                      "  p99.9 %.1f  max %.1f\n"
                      % (pw, name, p["clients"], p["p50"], p["p90"],
                         p["p99"], p["p99.9"], p["max"]))

    site = data["site"]

    if site:
        out.write("\nsite peak per window, banned clients left out:"
                  " %d requests, %.1f backend s (%.2f workers)\n"
                  % (site["requests"], site["backend_seconds"],
                     site["backend_seconds"] / judge.cfg.window))

    if not judge.timed:
        out.write("(no rt=/urt= in the log: requests, not backend"
                  " seconds)\n")


def report_ja4(judge, n, out=None):
    out = out or judge.out
    rows = top_ja4(judge, n)["fingerprints"]

    out.write("\nJA4 fingerprints by requests (allowlisted addresses are"
              " not judged, so not counted)\n")

    if not rows or (len(rows) == 1 and rows[0]["ja4"] == ""):
        out.write("(no ja4= in the log)\n")
        return

    out.write("%3s  %-36s %9s %6s %9s %6s %10s  %s\n"
              % ("#", "ja4", "requests", "share", "addresses", "banned",
                 "backend_s", "top user agent"))

    for i, r in enumerate(rows, 1):
        out.write("%3d  %-36s %9d %5.1f%% %9d %6d %10.1f  %d%% %s\n"
                  % (i, r["ja4"] or "(none)", r["requests"],
                     r["share"] * 100, r["addresses"], r["banned"],
                     r["backend_seconds"],
                     r["top_user_agent_requests"] * 100 // r["requests"],
                     (r["top_user_agent"] or "-")[:48]))

    # Commented out: pasting them all would give whatever else is in
    # the log, an attacker's script included, the app's limits.
    out.write("\n# Uncomment only your app's fingerprints; lines with one"
              " name OR.\n")

    for r in rows:
        if r["ja4"]:
            out.write("# profile app = ja4:^%s$    # %d banned, %s\n"
                      % (r["ja4"], r["banned"],
                         (r["top_user_agent"] or "-")[:48]))


def resolve_dns(name):
    """(names, addresses) for an address (reverse) or a name (forward)."""

    try:
        ipaddress.ip_address(name)

    except ValueError:
        try:
            return [name], {a[4][0] for a in socket.getaddrinfo(name, None)}

        except OSError:
            return [], set()

    try:
        host, aliases, _ = socket.gethostbyaddr(name)

    except OSError:
        return [], set()

    return [host] + aliases, set()


class NullOut:
    """Where --review and --explain send the ban lines they do not show:
    unlike open(os.devnull), nothing to close."""

    def write(self, s):
        pass

    def flush(self):
        pass


NULL_OUT = NullOut()


def dry_run(ip, ttl):
    return None


class Refused(str):
    """An error the daemon itself replied (a protected address, a full
    drop list, a failed map write): it would answer the same again, so
    the address is held for its ttl instead of retried every step."""


def ctl_drop(path):
    def drop(ip, ttl):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect(path)
                s.sendall(b"drop %s ttl=%d\n" % (ip.encode(), ttl))
                s.shutdown(socket.SHUT_WR)
                reply = b""

                while True:
                    chunk = s.recv(4096)

                    if not chunk:
                        break

                    reply += chunk

        except OSError as e:
            return '"%s"' % e

        reply = reply.decode(errors="replace").strip()

        if reply == "ok":
            return None

        if not reply:
            return '"no reply"'         # daemon died mid-request: retry

        return Refused('"%s"' % reply)

    return drop


def summarize(history, traffic):
    """One row per banned address: the most bans first, the repeat
    offenders; then the most costly requests, then the most requests.
    requests, costly and cost are the address's whole traffic in the
    log (traffic); the ttl is the last, longest, the replay reached."""

    rows = {}

    for now, ip, ttl, _, _, _, rule, note in history:
        r = rows.get(ip)

        if r is None:
            requests, costly, cost = traffic[ip]
            r = rows[ip] = {"ip": ip, "bans": 0, "requests": requests,
                            "costly": costly, "cost": cost, "rules": set(),
                            "notes": [], "first": now}

        r["bans"] += 1
        r["ttl"] = ttl
        r["rules"].add(rule)
        r["last"] = now

        if note and note not in r["notes"] and len(r["notes"]) < 5:
            r["notes"].append(note)

    return sorted(rows.values(), key=lambda r: (-r["bans"], -r["costly"],
                                                 -r["requests"], r["ip"]))


def print_rows(rows, out):
    width = max(len(r["ip"]) for r in rows)
    out.write("%3s  %-*s %5s %7s %8s %7s %6s %9s  %-13s %s\n"
              % ("#", width, "address", "bans", "ttl", "requests", "costly",
                 "ratio", "backend", "rule", "seen (UTC)"))

    for i, r in enumerate(rows, 1):
        seen = time.strftime("%m-%d %H:%M", time.gmtime(r["first"]))

        if r["last"] - r["first"] >= 60:
            # the end's date too, unless it is the same day
            same_day = (time.gmtime(r["first"])[:3]
                        == time.gmtime(r["last"])[:3])
            seen += time.strftime(" .. %H:%M" if same_day
                                  else " .. %m-%d %H:%M",
                                  time.gmtime(r["last"]))

        out.write("%3d  %-*s %5d %7d %8d %7d %6.2f %8.1fs  %-13s %s\n"
                  % (i, width, r["ip"], r["bans"], r["ttl"], r["requests"],
                     r["costly"], r["costly"] / r["requests"], r["cost"],
                     ",".join(sorted(r["rules"])), seen))


def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def rounded(v):
    """Floats to 4 decimals, all through v, for JSON output."""

    if isinstance(v, float):
        return round(v, 4)

    if isinstance(v, dict):
        return {k: rounded(x) for k, x in v.items()}

    if isinstance(v, list):
        return [rounded(x) for x in v]

    return v


def review(judge, out, as_json=False, extra=None):
    """The addresses the replay would ban, one row each, for a person or
    a console to decide on: nothing is sent. Text, or JSON; extra adds
    keys to the JSON object (the --top-* reports)."""

    rows = summarize(judge.history, judge.traffic)

    if as_json:
        # compact: jq or the console formats it
        json.dump(rounded(dict({
            "lines": judge.lines + judge.skipped,
            "unparsed": judge.skipped,
            "bans": [{"address": r["ip"], "ttl": r["ttl"],
                      "bans": r["bans"], "rules": sorted(r["rules"]),
                      "requests": r["requests"], "costly": r["costly"],
                      "ratio": round(r["costly"] / r["requests"], 4),
                      "backend_seconds": round(r["cost"], 3),
                      "first": iso(r["first"]), "last": iso(r["last"]),
                      "details": r["notes"]}
                     for r in rows],
        }, **(extra or {}))), out, separators=(",", ":"))
        out.write("\n")                     # formats it

    elif rows:
        print_rows(rows, out)

    else:
        out.write("nothing to ban\n")

    return 0


def read_files(paths):
    for path in paths:
        if path == "-":
            yield from sys.stdin
            continue

        opener = gzip.open if path.endswith(".gz") else open

        with opener(path, "rt", errors="replace") as f:
            yield from f


def follow(path, judge, from_start, poll=0.5):
    """tail -F: survive rotation and truncation, and move the window on
    wall-clock time while the log is quiet."""

    f = None
    partial = ""

    while True:
        if f is None:
            try:
                f = open(path, errors="replace")

            except FileNotFoundError:
                time.sleep(poll)
                continue

            ino = os.fstat(f.fileno()).st_ino

            if not from_start:
                f.seek(0, os.SEEK_END)

            from_start = True       # every later file is read whole

        line = f.readline()

        if line:
            if not line.endswith("\n"):
                partial += line
                continue

            judge.feed(partial + line)
            partial = ""
            continue

        judge.clock(time.time())
        time.sleep(poll)

        try:
            st = os.stat(path)

        except FileNotFoundError:
            continue

        if st.st_ino != ino or st.st_size < f.tell():
            f.close()
            f = None
            partial = ""


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Ban clients that spend their requests on costly URLs.")
    ap.add_argument("logs", nargs="+",
                    help="access log(s); .gz and - (stdin) work")
    ap.add_argument("-c", "--config", help="key = value config file")
    ap.add_argument("-n", "--dry-run", action="store_true",
                    help="print bans, send nothing")
    ap.add_argument("-f", "--follow", action="store_true",
                    help="follow one log like tail -F")
    ap.add_argument("-r", "--review", action="store_true",
                    help="replay and list what would be banned, one row per"
                         " address; sends nothing")
    ap.add_argument("--json", action="store_true",
                    help="with --review, list as JSON")
    ap.add_argument("-x", "--explain", metavar="IP",
                    help="replay as a dry run and show why IP was, or was"
                         " not, banned")
    ap.add_argument("--from-start", action="store_true",
                    help="with -f, read the existing file first")
    ap.add_argument("--top-paths", type=int, metavar="N", default=0,
                    help="at the end, print the N costliest paths")
    ap.add_argument("--top-clients", type=int, metavar="N", default=0,
                    help="at the end, print the N clients with the highest"
                         " peak backend seconds, and percentiles")
    ap.add_argument("--top-ja4", type=int, metavar="N", default=0,
                    help="at the end, print the N most used JA4"
                         " fingerprints, and profile lines for them")
    ap.add_argument("--top-allowed", type=int, metavar="N", default=0,
                    help="at the end, print allowlisted traffic (a CDN's)"
                         " per allowlist, and its N busiest addresses")
    ap.add_argument("-v", "--verbose", action="count", default=0)
    args = ap.parse_args(argv)

    cfg = Config()

    try:
        if args.config:
            cfg.load(args.config)

        else:
            cfg.check()

    except (OSError, ConfigError) as e:
        sys.stderr.write("logban: %s\n" % e)
        return 1

    act = dry_run if args.dry_run else ctl_drop(cfg.socket)

    if args.json and not args.review:
        sys.stderr.write("logban: --json goes with --review\n")
        return 1

    if args.explain:
        try:
            args.explain = str(ipaddress.ip_address(args.explain))

        except ValueError:
            sys.stderr.write("logban: --explain: not an address: %s\n"
                             % args.explain)
            return 1

        if args.follow or args.review:
            sys.stderr.write("logban: --explain replays logs, not with -f"
                             " or --review\n")
            return 1

        judge = Judge(cfg, dry_run, out=NULL_OUT,
                      verbose=args.verbose)
        judge.explain = Explain(args.explain, judge, sys.stdout)

    elif args.review:
        if args.follow:
            sys.stderr.write("logban: --review replays logs, not -f\n")
            return 1

        # A dry run: what to ban is decided elsewhere, a console say.
        judge = Judge(cfg, dry_run, out=NULL_OUT,
                      verbose=args.verbose)
        judge.history = []
        judge.traffic = {}

    else:
        judge = Judge(cfg, act, verbose=args.verbose)

    if args.top_clients:
        judge.peaks = {}

        if judge.load is None:
            judge.load = Load(cfg.window // cfg.step)

    if args.top_ja4:
        judge.ja4s = {}

    if args.top_allowed:
        judge.allowed = {"lines": 0, "sources": {}, "ips": {}}

    if args.follow:
        if len(args.logs) != 1 or args.logs[0] == "-":
            sys.stderr.write("logban: -f takes one log file\n")
            return 1

        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

        try:
            follow(args.logs[0], judge, args.from_start)

        except KeyboardInterrupt:
            return 0

    try:
        for line in read_files(args.logs):
            judge.feed(line)

    except OSError as e:
        sys.stderr.write("logban: %s\n" % e)
        return 1

    judge.finish()

    if args.verbose or args.top_paths or args.top_clients \
            or args.top_ja4 or args.top_allowed:
        sys.stderr.write("logban: %d lines, %d unparsed, %d allowed,"
                         " %d honey hits\n"
                         % (judge.lines + judge.skipped, judge.skipped,
                            judge.unjudged, judge.honey_hits))

    reports = [(n, data, text) for n, data, text in
               ((args.top_paths, top_paths, report_paths),
                (args.top_clients, top_clients, report_clients),
                (args.top_ja4, top_ja4, report_ja4),
                (args.top_allowed, top_allowed, report_allowed))
               if n]

    # One JSON object holds the bans and the reports.
    if args.review and args.json:
        return review(judge, sys.stdout, True, {
            data.__name__: data(judge, n) for n, data, _ in reports})

    if args.explain:
        judge.explain.summary()

    if args.review:
        review(judge, sys.stdout)

    # To stdout, after the bans: the replay's own output stream is
    # discarded by --review and --explain.
    for n, _, text in reports:
        text(judge, n, sys.stdout)

    return 0


if __name__ == "__main__":
    try:
        code = main()
        sys.stdout.flush()      # here, so a closed pipe is caught below
        sys.exit(code)

    except BrokenPipeError:
        # The reader went away (| head, a console that read enough):
        # exit quietly, and keep Python from failing on the final flush.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(1)
