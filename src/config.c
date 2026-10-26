
/* SPDX-License-Identifier: Apache-2.0 */

#include "config.h"
#include "log.h"

#include <ctype.h>
#include <errno.h>
#include <ifaddrs.h>
#include <limits.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


enum cfg_kind { CFG_STR, CFG_U64, CFG_I32, CFG_U32 };


struct cfg_scalar {
    const char     *key;
    enum cfg_kind   kind;
    size_t          off;
    size_t          sz;
};

#define CFG_OFF(f)  offsetof(struct vg_config, f)


static char *trim(char *s);
static int parse_u64(const char *s, uint64_t *out);
static int parse_int(const char *s, int *out);
static int parse_csv_cidrs(char *val, struct vg_cidr *arr, int *count,
    int max);
static int parse_allow_ports(char *val, struct vg_config *c);
static int apply_scalar(struct vg_config *c, const struct cfg_scalar *s,
    const char *val);
static int local_cidr_from_nic(const char *nic, struct vg_cidr *out,
    int max);


static const struct cfg_scalar scalars[] = {
    { "interface", CFG_STR, CFG_OFF(interface),
      sizeof(((struct vg_config *) NULL)->interface) },
    { "xdp_mode", CFG_STR, CFG_OFF(xdp_mode),
      sizeof(((struct vg_config *) NULL)->xdp_mode) },
    { "hook", CFG_STR, CFG_OFF(hook),
      sizeof(((struct vg_config *) NULL)->hook) },
    { "log_file", CFG_STR, CFG_OFF(log_file),
      sizeof(((struct vg_config *) NULL)->log_file) },
    { "pid_file", CFG_STR, CFG_OFF(pid_file),
      sizeof(((struct vg_config *) NULL)->pid_file) },
    { "wake_pps", CFG_U64, CFG_OFF(wake_pps), 0 },
    { "wake_mbps", CFG_U64, CFG_OFF(wake_mbps), 0 },
    { "idle_poll_ms", CFG_I32, CFG_OFF(idle_poll_ms), 0 },
    { "clear_seconds", CFG_I32, CFG_OFF(clear_seconds), 0 },
    { "threshold_pps", CFG_U64, CFG_OFF(threshold_pps), 0 },
    { "threshold_mbps", CFG_U64, CFG_OFF(threshold_mbps), 0 },
    { "ban_time", CFG_I32, CFG_OFF(ban_time), 0 },
    { "aggregate_k", CFG_I32, CFG_OFF(aggregate_k), 0 },
    { "metrics_port", CFG_I32, CFG_OFF(metrics_port), 0 },
    { "remote_map_size", CFG_U32, CFG_OFF(remote_map_size), 0 },
    { "drop_map_size", CFG_U32, CFG_OFF(drop_map_size), 0 },
    { "reply_idle_seconds", CFG_I32, CFG_OFF(reply_idle_seconds), 0 },
};


void
vg_config_defaults(struct vg_config *c)
{
    memset(c, 0, sizeof(*c));
    snprintf(c->interface, sizeof(c->interface), "eth0");
    snprintf(c->xdp_mode, sizeof(c->xdp_mode), "auto");
    snprintf(c->hook, sizeof(c->hook), "auto");
    snprintf(c->log_file, sizeof(c->log_file), "/var/log/voidgate.log");
    snprintf(c->pid_file, sizeof(c->pid_file), "/run/voidgate.pid");
    c->wake_pps = 2000;
    c->wake_mbps = 25;
    c->idle_poll_ms = 1000;
    c->clear_seconds = 30;
    c->threshold_pps = 500;
    c->threshold_mbps = 5;
    c->ban_time = 1900;
    c->aggregate_k = 8;
    c->metrics_port = 9105;
    c->remote_map_size = 262144;
    c->drop_map_size = 65536;
    c->reply_idle_seconds = 120;
    c->allow_ports[0] = 22;
    c->allow_port_count = 1;
    c->auto_local = 1;

    vg_parse_cidr("169.254.169.254/32", &c->allow_cidr[c->allow_cidr_count++]);
    vg_parse_cidr("127.0.0.0/8", &c->allow_cidr[c->allow_cidr_count++]);
    vg_parse_cidr("::1/128", &c->allow_cidr[c->allow_cidr_count++]);
    vg_parse_cidr("fe80::/10", &c->allow_cidr[c->allow_cidr_count++]);
    vg_parse_cidr("ff02::/16", &c->allow_cidr[c->allow_cidr_count++]);
}


static char *
trim(char *s)
{
    char *e;

    while (*s && isspace((unsigned char)*s))
        s++;
    e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1]))
        *--e = 0;

    return s;
}


static int
parse_u64(const char *s, uint64_t *out)
{
    char *end = NULL;
    unsigned long long v;

    if (s == NULL || *s == '\0') {
        return -1;
    }

    v = strtoull(s, &end, 10);

    if (end == s || *end != 0) {
        return -1;
    }

    *out = (uint64_t) v;

    return 0;
}


static int
parse_int(const char *s, int *out)
{
    uint64_t v;

    if (parse_u64(s, &v) < 0 || v > (uint64_t) INT_MAX) {
        return -1;
    }

    *out = (int) v;

    return 0;
}


static int
parse_csv_cidrs(char *val, struct vg_cidr *arr, int *count,
    int max)
{
    char *save = NULL;
    char *tok = strtok_r(val, ",", &save);

    while (tok != NULL) {
        tok = trim(tok);

        if (*tok) {
            if (*count >= max) {
                return -1;
            }

            if (vg_parse_cidr(tok, &arr[*count]) < 0) {
                vg_warn("bad CIDR '%s'", tok);
                return -1;
            }

            (*count)++;
        }

        tok = strtok_r(NULL, ",", &save);
    }

    return 0;
}


static int
parse_allow_ports(char *val, struct vg_config *c)
{
    char *save = NULL;
    char *tok = strtok_r(val, ",", &save);

    c->allow_port_count = 0;
    while (tok != NULL) {
        uint64_t v;

        tok = trim(tok);

        if (*tok) {
            if (c->allow_port_count >= VG_MAX_ALLOW_PORTS) {
                vg_warn("allow_ports: more than %d entries",
                        VG_MAX_ALLOW_PORTS);
                return -1;
            }

            if (parse_u64(tok, &v) < 0 || v < 1 || v > 65535) {
                vg_warn("bad allow port '%s'", tok);
                return -1;
            }

            c->allow_ports[c->allow_port_count++] = (uint16_t) v;
        }

        tok = strtok_r(NULL, ",", &save);
    }

    return 0;
}


static int
apply_scalar(struct vg_config *c, const struct cfg_scalar *s,
    const char *val)
{
    switch (s->kind) {
    case CFG_STR:
        if (s->sz == 0 || *val == '\0' || strlen(val) >= s->sz) {
            return -1;
        }

        snprintf((char *) c + s->off, s->sz, "%s", val);
        return 0;
    case CFG_U64: {
        uint64_t v;

        if (parse_u64(val, &v) < 0) {
            return -1;
        }

        *(uint64_t *) ((char *) c + s->off) = v;
        return 0;
    }
    case CFG_I32: {
        int v;

        if (parse_int(val, &v) < 0) {
            return -1;
        }

        *(int *) ((char *) c + s->off) = v;
        return 0;
    }
    case CFG_U32: {
        uint64_t v;

        if (parse_u64(val, &v) < 0 || v > 0xffffffffULL) {
            return -1;
        }

        *(uint32_t *) ((char *) c + s->off) = (uint32_t) v;
        return 0;
    }
    }

    return -1;
}


int
vg_config_load(const char *path, struct vg_config *c)
{
    FILE *fp;
    char *line = NULL;
    size_t cap = 0;
    int lineno = 0;
    int local_seen = 0, allow_seen = 0;

    vg_config_defaults(c);

    if (path == NULL) {
        return 0;
    }

    fp = fopen(path, "r");

    if (fp == NULL) {
        vg_warn("config %s not found, using defaults", path);
        return 0;
    }

    /* getline, not a fixed buffer: a CSV list (up to VG_MAX_CIDR_LIST
     * entries) split mid-token would parse the pieces as other prefixes.
     */
    while (getline(&line, &cap, fp) != -1) {
        char *eq, *key, *val;
        size_t i;
        int found = 0;

        lineno++;

        if (line[0] == '#' || line[0] == '\n' || line[0] == 0) {
            continue;
        }

        eq = strchr(line, '=');

        if (eq == NULL) {
            continue;
        }

        *eq = 0;
        key = trim(line);
        val = trim(eq + 1);

        if (*key == '\0') {
            continue;
        }

        for (i = 0; i < sizeof(scalars) / sizeof(scalars[0]); i++) {
            if (strcmp(key, scalars[i].key) != 0) {
                continue;
            }

            if (apply_scalar(c, &scalars[i], val) < 0) {
                vg_warn("%s:%d: bad value for %s", path, lineno, key);
                goto fail;
            }

            found = 1;
            break;
        }

        if (found) {
            continue;
        }

        if (strcmp(key, "allow_ports") == 0) {
            if (parse_allow_ports(val, c) < 0) {
                goto fail;
            }

        } else if (strcmp(key, "local_networks") == 0) {
            if (*val) {
                c->auto_local = 0;

                if (!local_seen) {
                    c->local_cidr_count = 0;
                    local_seen = 1;
                }

                if (parse_csv_cidrs(val, c->local_cidr, &c->local_cidr_count,
                                    VG_MAX_CIDR_LIST) < 0)
                {
                    goto fail;
                }
            }

        } else if (strcmp(key, "allow_networks") == 0) {
            /* The first list replaces the built-in one; later lines add
             * to it, so a second line cannot drop the first.
             */
            if (*val) {
                if (!allow_seen) {
                    c->allow_cidr_count = 0;
                    allow_seen = 1;
                }

                if (parse_csv_cidrs(val, c->allow_cidr, &c->allow_cidr_count,
                                    VG_MAX_CIDR_LIST) < 0)
                {
                    goto fail;
                }
            }

        } else {
            vg_warn("%s:%d: unknown key '%s'", path, lineno, key);
        }
    }

    if (ferror(fp)) {
        vg_warn("%s: read error: %s", path, strerror(errno));
        goto fail;
    }

    free(line);
    fclose(fp);

    if (c->idle_poll_ms <= 0) {
        c->idle_poll_ms = 1000;
    }

    if (c->reply_idle_seconds <= 0) {
        c->reply_idle_seconds = 120;
    }

    return 0;

fail:
    free(line);
    fclose(fp);

    return -1;
}


/* This VM's addresses as host CIDRs (/32, /128). The on-link netmask
 * is not used: a neighbor on the same LAN is not local.
 */
static int
local_cidr_from_nic(const char *nic, struct vg_cidr *out, int max)
{
    struct ifaddrs *ifa, *p;
    int n = 0;

    if (getifaddrs(&ifa) < 0) {
        vg_warn("getifaddrs failed: %s", strerror(errno));
        return -1;
    }

    for (p = ifa; p != NULL && n < max; p = p->ifa_next) {
        if (p->ifa_addr == NULL || p->ifa_name == NULL
            || strcmp(p->ifa_name, nic) != 0)
        {
            continue;
        }

        if (p->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *a = (struct sockaddr_in *) p->ifa_addr;

            if (((const uint8_t *) &a->sin_addr)[0] == 127) {
                continue;
            }

            memset(&out[n], 0, sizeof(out[n]));
            out[n].family = AF_INET;
            memcpy(out[n].addr, &a->sin_addr, 4);
            out[n].prefixlen = 32;
            n++;

        } else if (p->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *a = (struct sockaddr_in6 *) p->ifa_addr;

            if (IN6_IS_ADDR_LINKLOCAL(&a->sin6_addr)
                || IN6_IS_ADDR_LOOPBACK(&a->sin6_addr))
            {
                continue;
            }

            memset(&out[n], 0, sizeof(out[n]));
            out[n].family = AF_INET6;
            memcpy(out[n].addr, &a->sin6_addr, 16);
            out[n].prefixlen = 128;
            n++;
        }
    }

    freeifaddrs(ifa);

    return n;
}


int
vg_config_auto_local(struct vg_config *c)
{
    int n;

    if (!c->auto_local) {
        return 0;
    }

    n = local_cidr_from_nic(c->interface, c->local_cidr, VG_MAX_CIDR_LIST);

    if (n < 0) {
        return -1;
    }

    c->local_cidr_count = n;

    return 0;
}


int
vg_cidr_is_protected(const struct vg_config *cfg,
    const struct vg_cidr *p)
{
    int i;

    for (i = 0; i < cfg->local_cidr_count; i++) {
        if (vg_cidr_covers_or_overlaps(p, &cfg->local_cidr[i])) {
            return 1;
        }
    }

    for (i = 0; i < cfg->allow_cidr_count; i++) {
        if (vg_cidr_covers_or_overlaps(p, &cfg->allow_cidr[i])) {
            return 1;
        }
    }

    return 0;
}
