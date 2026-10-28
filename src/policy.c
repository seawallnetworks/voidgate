
/* SPDX-License-Identifier: Apache-2.0 */

#include "policy.h"
#include "log.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


struct vg_snap_ent {
    int                  family;
    uint8_t              addr[16];
    uint64_t             in_pkts;
    uint64_t             in_bytes;
    uint32_t             gen;
    struct vg_snap_ent  *next;
};


static unsigned snap_hash(int family, const uint8_t *addr);
static void snap_reset_pool(struct vg_ctrl *c);
static void snap_clear(struct vg_ctrl *c);
static void snap_prune(struct vg_ctrl *c);
static struct vg_snap_ent *snap_get(struct vg_ctrl *c, int family,
    const uint8_t *addr, int *created);
static unsigned drop_hash(const struct vg_ctrl *c, const struct vg_cidr *p);
static struct vg_drop_rec *drops_find(struct vg_ctrl *c,
    const struct vg_cidr *p);
static struct vg_drop_rec *drop_alloc(struct vg_ctrl *c);
static void drops_reset(struct vg_ctrl *c);
static int drop_remove(struct vg_ctrl *c, struct vg_drop_rec *r);
static int drop_add(struct vg_ctrl *c, const struct vg_cidr *p,
    uint32_t reason, time_t expires);
static int maybe_aggregate(struct vg_ctrl *c, const struct vg_cidr *host);
static void policy_one_remote(struct vg_ctrl *c, int family,
    const uint8_t *addr, const struct host_counters *cur, double dt);
static void remote_cb(int family, const uint8_t *addr,
    const struct host_counters *sum, void *arg);
static void walk_remotes(struct vg_ctrl *c, double dt);
static void expire_drops(struct vg_ctrl *c);
static const char *reason_name(uint32_t reason);
static void logged_list(char *out, size_t size,
    const struct vg_logged_drop *v, int n);
static void log_drops(struct vg_ctrl *c);
static double tick_dt(struct vg_ctrl *c);


static unsigned
snap_hash(int family, const uint8_t *addr)
{
    unsigned h = (unsigned) family * 16777619u;
    int n = family == AF_INET ? 4 : 16;
    int i;

    for (i = 0; i < n; i++) {
        h = (h ^ addr[i]) * 16777619u;
    }

    return h % VG_SNAP_BUCKETS;
}


static void
snap_reset_pool(struct vg_ctrl *c)
{
    unsigned i;

    for (i = 0; i < VG_SNAP_BUCKETS; i++) {
        c->snaps[i] = NULL;
    }

    c->snap_free = NULL;

    if (c->snap_pool == NULL || !c->snap_cap) {
        return;
    }

    for (i = 0; i < c->snap_cap; i++) {
        c->snap_pool[i].gen = 0;
        c->snap_pool[i].next = i + 1 < c->snap_cap
                               ? &c->snap_pool[i + 1] : NULL;
    }

    c->snap_free = c->snap_pool;
}


static void
snap_clear(struct vg_ctrl *c)
{
    snap_reset_pool(c);
}


/* Reclaim remotes missing from a complete map scan. Truncated walks must not
 * call this — rate snapshots for unvisited keys have to survive churn.
 */
static void
snap_prune(struct vg_ctrl *c)
{
    int i;

    for (i = 0; i < VG_SNAP_BUCKETS; i++) {
        struct vg_snap_ent **link = &c->snaps[i];

        while (*link != NULL) {
            struct vg_snap_ent *e = *link;

            if (e->gen != c->snap_gen) {
                *link = e->next;
                e->gen = 0;
                e->next = c->snap_free;
                c->snap_free = e;

            } else {
                link = &e->next;
            }
        }
    }
}


static struct vg_snap_ent *
snap_get(struct vg_ctrl *c, int family, const uint8_t *addr, int *created)
{
    unsigned h = snap_hash(family, addr);
    struct vg_snap_ent *e;
    int n = family == AF_INET ? 4 : 16;

    *created = 0;

    for (e = c->snaps[h]; e != NULL; e = e->next) {
        if (e->family == family && memcmp(e->addr, addr, (size_t) n) == 0) {
            e->gen = c->snap_gen;
            return e;
        }
    }

    e = c->snap_free;

    if (e == NULL) {
        return NULL;
    }

    c->snap_free = e->next;
    e->family = family;
    memcpy(e->addr, addr, (size_t) n);
    e->in_pkts = 0;
    e->in_bytes = 0;
    e->gen = c->snap_gen;
    e->next = c->snaps[h];
    c->snaps[h] = e;

    *created = 1;

    return e;
}


int
vg_ctrl_init(struct vg_ctrl *c, struct vg_config *cfg,
    struct vg_maps *maps, const char *cfg_path,
    const char *iface_ov)
{
    memset(c, 0, sizeof(*c));
    c->cfg = cfg;
    c->maps = maps;
    c->state = VG_IDLE;
    /* drop_v4 and drop_v6 each hold up to drop_map_size prefixes, and
     * reload cannot grow them: one record per possible entry, never moved.
     * calloc pages stay untouched until drop_alloc reaches them.
     */
    c->drop_pool_cap = 2 * (cfg != NULL && cfg->drop_map_size != 0
                            ? cfg->drop_map_size : VG_DROP_MAP_MAX);
    c->drop_nbuckets = 1024;

    while (c->drop_nbuckets < c->drop_pool_cap) {
        c->drop_nbuckets <<= 1;
    }

    c->drop_pool = calloc(c->drop_pool_cap, sizeof(*c->drop_pool));
    c->drop_heads = calloc(c->drop_nbuckets, sizeof(*c->drop_heads));

    if (c->drop_pool == NULL || c->drop_heads == NULL) {
        free(c->drop_pool);
        free(c->drop_heads);
        c->drop_pool = NULL;
        c->drop_heads = NULL;
        return -1;
    }

    vg_list_init(&c->drop_free);
    vg_list_init(&c->drop_all);

    c->snap_cap = (cfg != NULL && cfg->remote_map_size != 0)
                  ? cfg->remote_map_size * 2 : VG_REMOTE_MAP_MAX * 2;
    c->snap_pool = calloc((size_t) c->snap_cap, sizeof(*c->snap_pool));

    if (c->snap_pool == NULL) {
        free(c->drop_pool);
        free(c->drop_heads);
        c->drop_pool = NULL;
        c->drop_heads = NULL;
        return -1;
    }

    snap_reset_pool(c);

    if (cfg_path != NULL) {
        snprintf(c->cfg_path, sizeof(c->cfg_path), "%s", cfg_path);
    }

    if (iface_ov != NULL) {
        snprintf(c->iface_override, sizeof(c->iface_override), "%s", iface_ov);
    }

    return 0;
}


void
vg_ctrl_free(struct vg_ctrl *c)
{
    free(c->drop_pool);
    c->drop_pool = NULL;
    free(c->drop_heads);
    c->drop_heads = NULL;
    free(c->snap_pool);
    c->snap_pool = NULL;
    c->snap_free = NULL;
    c->snap_cap = 0;
}


/* Every listed drop is on drop_all (oldest first, for walks) and in the
 * drop_heads bucket of its prefix (for lookups). prefixlen is part of the
 * key: 198.18.0.1/32 and 198.18.0.0/24 are separate drops.
 */
static unsigned
drop_hash(const struct vg_ctrl *c, const struct vg_cidr *p)
{
    unsigned h = (unsigned) p->family * 16777619u;
    int n = p->family == AF_INET ? 4 : 16;
    int i;

    h = (h ^ p->prefixlen) * 16777619u;

    for (i = 0; i < n; i++) {
        h = (h ^ p->addr[i]) * 16777619u;
    }

    return h & (c->drop_nbuckets - 1);
}


static struct vg_drop_rec *
drops_find(struct vg_ctrl *c, const struct vg_cidr *p)
{
    struct vg_hlist_node *n;
    struct vg_drop_rec *r;

    for (n = c->drop_heads[drop_hash(c, p)].first; n != NULL; n = n->next) {
        r = vg_list_entry(n, struct vg_drop_rec, hash);

        if (r->cidr.family == p->family
            && r->cidr.prefixlen == p->prefixlen
            && memcmp(r->cidr.addr, p->addr,
                      p->family == AF_INET ? 4 : 16) == 0)
        {
            return r;
        }
    }

    return NULL;
}


/* A lifted record if there is one, else the next never-used pool record;
 * NULL when every record is listed (both drop maps full).
 */
static struct vg_drop_rec *
drop_alloc(struct vg_ctrl *c)
{
    struct vg_list *l;

    if (!vg_list_empty(&c->drop_free)) {
        l = c->drop_free.next;
        vg_list_del(l);
        return vg_list_entry(l, struct vg_drop_rec, all);
    }

    if (c->drop_used < c->drop_pool_cap) {
        return &c->drop_pool[c->drop_used++];
    }

    return NULL;
}


/* Forget every record at once (disarm flushed the maps). */
static void
drops_reset(struct vg_ctrl *c)
{
    memset(c->drop_heads, 0, c->drop_nbuckets * sizeof(*c->drop_heads));
    vg_list_init(&c->drop_free);
    vg_list_init(&c->drop_all);
    c->drop_used = 0;
    c->drop_count = 0;
}


/* Lift r: kernel map first, so a failed delete keeps the record (still
 * listed, retried by the next expiry pass) instead of leaving a map entry
 * nothing tracks. r stays readable until the next drop_alloc. Logs only a
 * failure; callers log the lift (expiry sums them per tick).
 */
static int
drop_remove(struct vg_ctrl *c, struct vg_drop_rec *r)
{
    char buf[80];

    if (vg_drop_del(c->maps, &r->cidr) < 0 && errno != ENOENT) {
        vg_cidr_to_str(&r->cidr, buf, sizeof(buf));
        sw_log_warn("undrop map delete %s failed: %s", buf, strerror(errno));
        return -1;
    }

    vg_hlist_del(&r->hash);
    vg_list_del(&r->all);
    vg_list_add_tail(&r->all, &c->drop_free);
    c->drop_count--;

    return 0;
}


/* expires is the wall-clock lift time of a VG_REASON_TIMED drop, else 0.
 * Re-dropping a listed prefix: manual wins over everything and never
 * expires; timed replaces policy/aggregate and only ever extends; a policy
 * or aggregate re-drop leaves the record alone.
 */
static int
drop_add(struct vg_ctrl *c, const struct vg_cidr *p, uint32_t reason,
    time_t expires)
{
    char buf[80];
    time_t now = time(NULL);
    struct vg_drop_rec *r;
    int again;

    vg_cidr_to_str(p, buf, sizeof(buf));

    if (vg_cidr_is_protected(c->cfg, p)) {
        sw_log_info("refuse drop %s (covers local/allow)", buf);
        return -1;
    }

    if (c->state != VG_ACTIVE && vg_ctrl_arm(c, "manual drop") < 0) {
        return -1;
    }

    r = drops_find(c, p);
    again = r != NULL;

    if (r == NULL) {
        r = drop_alloc(c);

        if (r == NULL) {
            sw_log_warn("drop %s refused: drop list full (%u)", buf,
                        c->drop_pool_cap);
            return -1;
        }

        if (vg_drop_add(c->maps, p, reason, (uint32_t) now) < 0) {
            sw_log_warn("drop map update %s failed: %s", buf, strerror(errno));
            vg_list_add_tail(&r->all, &c->drop_free);
            return -1;
        }

        r->cidr = *p;
        r->reason = reason;
        r->inserted = now;
        r->expires = expires;
        vg_hlist_add_head(&r->hash, &c->drop_heads[drop_hash(c, p)]);
        vg_list_add_tail(&r->all, &c->drop_all);
        c->drop_count++;

    } else {

        if (reason == VG_REASON_TIMED) {
            if (r->reason == VG_REASON_MANUAL) {
                return 0;
            }

            if (r->reason != VG_REASON_TIMED) {
                r->expires = r->inserted + c->cfg->ban_time;
            }

            if (expires < r->expires) {
                expires = r->expires;
            }
        }

        if (vg_drop_add(c->maps, p, reason, (uint32_t) now) < 0) {
            sw_log_warn("drop map update %s failed: %s", buf, strerror(errno));
            return -1;
        }

        if (reason == VG_REASON_MANUAL || reason == VG_REASON_TIMED) {
            r->reason = reason;
            r->inserted = now;
            r->expires = expires;
        }
    }

    sw_log_debug("drop %s (%s)%s", buf, reason_name(reason),
                 again ? " again" : "");

    if (again) {
        c->drops_again++;

    } else {
        c->drops_new[reason <= VG_REASON_TIMED ? reason : 0]++;

        if (c->drops_shown_n < VG_LOG_CIDRS) {
            c->drops_shown[c->drops_shown_n].cidr = *p;
            c->drops_shown[c->drops_shown_n].reason = reason;
            c->drops_shown_n++;
        }
    }

    return 0;
}


int
vg_ctrl_drop(struct vg_ctrl *c, const struct vg_cidr *p, uint32_t reason)
{
    return drop_add(c, p, reason, 0);
}


int
vg_ctrl_drop_ttl(struct vg_ctrl *c, const struct vg_cidr *p, uint32_t ttl)
{
    return drop_add(c, p, VG_REASON_TIMED, time(NULL) + (time_t) ttl);
}


int
vg_ctrl_undrop(struct vg_ctrl *c, const struct vg_cidr *p)
{
    char buf[80];
    struct vg_drop_rec *r = drops_find(c, p);

    log_drops(c);
    vg_cidr_to_str(p, buf, sizeof(buf));

    if (r != NULL) {
        if (drop_remove(c, r) < 0) {
            return -1;
        }

    /* Not listed: still clear a stray map entry. */
    } else if (vg_drop_del(c->maps, p) < 0 && errno != ENOENT) {
        sw_log_warn("undrop map delete %s failed: %s", buf, strerror(errno));
        return -1;
    }

    sw_log_info("undrop %s", buf);

    return 0;
}


/* After cfg changes (reload): lift every drop, manual ones included, that
 * now covers local_* or allow_*. vg_ctrl_drop refuses such a prefix, and
 * XDP matches drops on the destination too, so one left in place would
 * blackhole a new local address. Returns the number lifted.
 */
int
vg_ctrl_prune_protected(struct vg_ctrl *c)
{
    char buf[80];
    struct vg_list *l, *next;
    struct vg_drop_rec *r;
    int n = 0;

    log_drops(c);

    vg_list_for_each_safe(l, next, &c->drop_all) {
        r = vg_list_entry(l, struct vg_drop_rec, all);

        if (!vg_cidr_is_protected(c->cfg, &r->cidr)) {
            continue;
        }

        vg_cidr_to_str(&r->cidr, buf, sizeof(buf));
        sw_log_warn("reload: undrop %s (now covers local/allow)", buf);

        if (drop_remove(c, r) == 0) {
            n++;
        }
    }

    return n;
}


int
vg_ctrl_arm(struct vg_ctrl *c, const char *why)
{
    if (c->state == VG_ACTIVE) {
        return 0;
    }

    snap_clear(c);
    c->quiet_since = 0;

    if (vg_cfg_commit(c->maps, 1, c->cfg) < 0) {
        sw_log_warn("arm cfg commit failed: %s", strerror(errno));
        return -1;
    }

    c->state = VG_ACTIVE;
    sw_log_info("armed (%s)", why != NULL ? why : "");

    return 0;
}


int
vg_ctrl_disarm(struct vg_ctrl *c, const char *why)
{
    log_drops(c);
    vg_drop_flush(c->maps);
    drops_reset(c);

    if (vg_cfg_commit(c->maps, 0, c->cfg) < 0) {
        sw_log_warn("disarm cfg commit failed: %s", strerror(errno));
        return -1;
    }

    c->state = VG_IDLE;
    c->quiet_since = 0;
    sw_log_info("disarmed (%s)", why != NULL ? why : "");

    return 0;
}


static int
maybe_aggregate(struct vg_ctrl *c, const struct vg_cidr *host)
{
    struct vg_cidr net;
    struct vg_list *l;
    struct vg_drop_rec *r;
    int n = 0;

    if (host->family == AF_INET) {
        if (vg_cidr_v4_slash24(host, &net) < 0) {
            return 0;
        }

    } else {
        if (vg_cidr_v6_slash64(host, &net) < 0) {
            return 0;
        }
    }

    /* Timed drops come from outside (an L7 ban): many users behind one
     * NAT /24 must not turn a few web bans into a prefix drop.
     */
    for (l = c->drop_all.next; l != &c->drop_all; l = l->next) {
        r = vg_list_entry(l, struct vg_drop_rec, all);

        if (r->reason != VG_REASON_TIMED && vg_cidr_contains(&net, &r->cidr)) {
            n++;
        }
    }

    if (n >= c->cfg->aggregate_k) {
        return vg_ctrl_drop(c, &net, VG_REASON_AGGREGATE);
    }

    return 0;
}


static void
policy_one_remote(struct vg_ctrl *c, int family,
    const uint8_t *addr,
    const struct host_counters *cur, double dt)
{
    int created = 0;
    struct vg_snap_ent *s = snap_get(c, family, addr, &created);
    uint64_t dp, db;
    double pps, bps;
    struct vg_cidr p;
    char buf[80];

    if (s == NULL) {
        return;
    }

    if (created) {
        s->in_pkts = cur->in_pkts;
        s->in_bytes = cur->in_bytes;
        return;
    }

    dp = cur->in_pkts >= s->in_pkts ? cur->in_pkts - s->in_pkts : 0;
    db = cur->in_bytes >= s->in_bytes ? cur->in_bytes - s->in_bytes : 0;
    s->in_pkts = cur->in_pkts;
    s->in_bytes = cur->in_bytes;

    if (dt <= 0) {
        return;
    }

    pps = (double) dp / dt;
    bps = (double) db * 8.0 / dt;

    if (pps < (double) c->cfg->threshold_pps
        && bps < (double) c->cfg->threshold_mbps * 1000000.0)
    {
        return;
    }

    memset(&p, 0, sizeof(p));
    p.family = family;
    memcpy(p.addr, addr, family == AF_INET ? 4 : 16);
    p.prefixlen = family == AF_INET ? 32 : 128;
    vg_cidr_to_str(&p, buf, sizeof(buf));
    vg_vvlog("remote %s %.0f pps %.1f Mbps", buf, pps, bps / 1e6);

    if (vg_ctrl_drop(c, &p, VG_REASON_POLICY) == 0) {
        maybe_aggregate(c, &p);

    } else {
        vg_vvlog("remote %s over threshold, not dropped", buf);
    }
}


struct vg_walk_ctx {
    struct vg_ctrl  *c;
    double           dt;
};

static void
remote_cb(int family, const uint8_t *addr,
    const struct host_counters *sum, void *arg)
{
    struct vg_walk_ctx *w = arg;

    policy_one_remote(w->c, family, addr, sum, w->dt);
}


static void
walk_remotes(struct vg_ctrl *c, double dt)
{
    struct vg_walk_ctx w = { .c = c, .dt = dt };
    uint32_t budget = c->cfg->remote_map_size;
    int complete;

    if (budget == 0) {
        budget = VG_REMOTE_MAP_MAX;
    }

    c->snap_gen++;

    if (c->snap_gen == 0) {
        snap_reset_pool(c);
        c->snap_gen = 1;
    }

    complete = vg_remote_foreach(c->maps, budget, remote_cb, &w);

    if (complete == 1) {
        snap_prune(c);

    } else if (complete == 0) {
        vg_vvlog("remote walk truncated");

    } else {
        vg_vvlog("remote walk failed");
    }
}


/* One log line per tick for everything that expired, however many: a burst
 * of web bans can lift thousands at once. -v adds a line per prefix.
 */
static void
expire_drops(struct vg_ctrl *c)
{
    time_t now = time(NULL);
    struct vg_list *l, *next;
    struct vg_drop_rec *r;
    char buf[80], list[VG_LOG_CIDRS * 64];
    struct vg_logged_drop shown[VG_LOG_CIDRS];
    int n = 0, by[VG_REASON_TIMED + 1] = { 0 };

    vg_list_for_each_safe(l, next, &c->drop_all) {
        r = vg_list_entry(l, struct vg_drop_rec, all);

        if (r->reason == VG_REASON_MANUAL
            || (r->reason == VG_REASON_TIMED
                ? now < r->expires
                : now - r->inserted < c->cfg->ban_time))
        {
            continue;
        }

        /* Copied first: drop_remove hands r back to the free list. */
        if (n < VG_LOG_CIDRS) {
            shown[n].cidr = r->cidr;
            shown[n].reason = r->reason;
        }

        /* A failed lift keeps r listed; the next tick retries it. */
        if (drop_remove(c, r) < 0) {
            continue;
        }

        if (sw_log_enabled(SW_LOG_DEBUG)) {
            vg_cidr_to_str(&r->cidr, buf, sizeof(buf));
            sw_log_debug("expire %s (%s)", buf, reason_name(r->reason));
        }

        by[r->reason <= VG_REASON_TIMED ? r->reason : 0]++;
        n++;
    }

    if (n == 0) {
        return;
    }

    logged_list(list, sizeof(list), shown, n);

    if (n <= VG_LOG_CIDRS) {
        sw_log_info("expired %s; %d left", list, c->drop_count);

    } else {
        sw_log_info("expired %d drops (policy %d, aggregate %d, timed %d), "
                    "first %s; %d left", n, by[VG_REASON_POLICY],
                    by[VG_REASON_AGGREGATE], by[VG_REASON_TIMED], list,
                    c->drop_count);
    }
}


static const char *
reason_name(uint32_t reason)
{
    switch (reason) {
    case VG_REASON_MANUAL:
        return "manual";
    case VG_REASON_POLICY:
        return "policy";
    case VG_REASON_AGGREGATE:
        return "aggregate";
    case VG_REASON_TIMED:
        return "timed";
    default:
        return "unknown";
    }
}


/* "203.0.113.7/32 (policy), 198.51.100.0/24 (aggregate)": the first
 * VG_LOG_CIDRS of n, so a burst still logs one short line.
 */
static void
logged_list(char *out, size_t size, const struct vg_logged_drop *v, int n)
{
    char buf[80];
    size_t used = 0;
    int i, w;

    out[0] = '\0';

    for (i = 0; i < n && i < VG_LOG_CIDRS; i++) {
        vg_cidr_to_str(&v[i].cidr, buf, sizeof(buf));
        w = snprintf(out + used, size - used, "%s%s (%s)", i ? ", " : "",
                     buf, reason_name(v[i].reason));

        if (w < 0 || (size_t) w >= size - used) {
            break;
        }

        used += (size_t) w;
    }
}


/* One log line per tick for every drop added since the last one, however
 * many: a ban burst can add thousands. It names the first VG_LOG_CIDRS
 * prefixes; -v adds a line per prefix. An undrop, a disarm or a reload
 * lift logs the pending line first, so the log keeps its order and never
 * names a prefix as dropped after it was lifted.
 */
static void
log_drops(struct vg_ctrl *c)
{
    char list[VG_LOG_CIDRS * 64], again[32];
    int i, n = 0;

    for (i = 0; i <= VG_REASON_TIMED; i++) {
        n += c->drops_new[i];
    }

    again[0] = '\0';

    if (c->drops_again > 0) {
        snprintf(again, sizeof(again), "%d again, ", c->drops_again);
    }

    if (n == 0 && c->drops_again > 0) {
        sw_log_info("dropped %d listed prefix%s again; %d listed",
                    c->drops_again, c->drops_again == 1 ? "" : "es",
                    c->drop_count);

    } else if (n > 0) {
        logged_list(list, sizeof(list), c->drops_shown, c->drops_shown_n);

        if (n <= VG_LOG_CIDRS) {
            sw_log_info("dropped %s; %s%d listed", list, again, c->drop_count);

        } else {
            sw_log_info("dropped %d prefixes (manual %d, policy %d, "
                        "aggregate %d, timed %d), first %s; %s%d listed", n,
                        c->drops_new[VG_REASON_MANUAL],
                        c->drops_new[VG_REASON_POLICY],
                        c->drops_new[VG_REASON_AGGREGATE],
                        c->drops_new[VG_REASON_TIMED], list, again,
                        c->drop_count);
        }
    }

    memset(c->drops_new, 0, sizeof(c->drops_new));
    c->drops_again = 0;
    c->drops_shown_n = 0;
}


static double
tick_dt(struct vg_ctrl *c)
{
    struct timespec now;
    double dt;

    clock_gettime(CLOCK_MONOTONIC, &now);

    if (c->have_last_tick == 0) {
        c->last_tick = now;
        c->have_last_tick = 1;
        return 0;
    }

    dt = (double) (now.tv_sec - c->last_tick.tv_sec)
         + (double) (now.tv_nsec - c->last_tick.tv_nsec) / 1e9;
    c->last_tick = now;

    return dt;
}


int
vg_ctrl_tick(struct vg_ctrl *c)
{
    struct vg_metrics m;
    double dt = tick_dt(c);
    double drop_pps = 0;

    /* Drops since the last tick, including ones a disarm since lifted. */
    log_drops(c);

    if (vg_metrics_read(c->maps, &m) < 0) {
        return -1;
    }

    if (c->have_last_m && dt > 0) {
        uint64_t dp = m.rx_pkts >= c->last_m.rx_pkts
                      ? m.rx_pkts - c->last_m.rx_pkts : 0;
        uint64_t db = m.rx_bytes >= c->last_m.rx_bytes
                      ? m.rx_bytes - c->last_m.rx_bytes : 0;
        uint64_t dd = m.dropped >= c->last_m.dropped
                      ? m.dropped - c->last_m.dropped : 0;

        c->rx_pps = (double) dp / dt;
        c->rx_bps = (double) db * 8.0 / dt;
        drop_pps = (double) dd / dt;
    }

    c->last_m = m;
    c->have_last_m = 1;

    if (dt <= 0) {
        return 0;
    }

    if (c->state == VG_IDLE) {
        vg_vvlog("tick %-6s rx(pps)=%-8.0f rx(Mbps)=%-6.1f",
                 "idle", c->rx_pps, c->rx_bps / 1e6);

        if (c->rx_pps > (double) c->cfg->wake_pps
            || c->rx_bps > (double) c->cfg->wake_mbps * 1000000.0)
        {
            vg_ctrl_arm(c, "wake threshold");
        }

        return 0;
    }

    walk_remotes(c, dt);
    expire_drops(c);

    sw_log_debug("tick %-6s rx(pps)=%-8.0f rx(Mbps)=%-6.1f "
                 "dropped(pps)=%-8.0f prefixes=%d",
                 "active", c->rx_pps, c->rx_bps / 1e6, drop_pps, c->drop_count);

    if (c->rx_pps < (double) c->cfg->wake_pps
        && c->rx_bps < (double) c->cfg->wake_mbps * 1000000.0)
    {
        if (c->quiet_since == 0) {
            c->quiet_since = time(NULL);
        }

        if (c->drop_count == 0
            && time(NULL) - c->quiet_since >= c->cfg->clear_seconds)
        {
            vg_ctrl_disarm(c, "attack cleared");
        }

    } else {
        c->quiet_since = 0;
    }

    return 0;
}


#if (VG_CTRL_TEST)
unsigned
vg_ctrl_snap_count(const struct vg_ctrl *c)
{
    unsigned n = 0;
    int i;

    for (i = 0; i < VG_SNAP_BUCKETS; i++) {
        const struct vg_snap_ent *e;

        for (e = c->snaps[i]; e != NULL; e = e->next) {
            n++;
        }
    }

    return n;
}


struct vg_drop_rec *
vg_ctrl_drops_find(struct vg_ctrl *c, const struct vg_cidr *p)
{
    return drops_find(c, p);
}


/* The lists are consistent: drop_all and the buckets hold the same
 * drop_count records, every link agrees with its neighbour, each record
 * sits in the bucket its prefix hashes to, and a lookup returns it.
 */
int
vg_ctrl_drops_check(struct vg_ctrl *c)
{
    struct vg_hlist_node *n, **pprev;
    struct vg_list *l;
    struct vg_drop_rec *r;
    unsigned b;
    int listed = 0, hashed = 0;

    for (l = c->drop_all.next; l != &c->drop_all; l = l->next) {
        r = vg_list_entry(l, struct vg_drop_rec, all);

        if (l->next->prev != l || r < c->drop_pool
            || r >= c->drop_pool + c->drop_used
            || drops_find(c, &r->cidr) != r || ++listed > c->drop_count)
        {
            return -1;
        }
    }

    for (b = 0; b < c->drop_nbuckets; b++) {
        pprev = &c->drop_heads[b].first;

        for (n = *pprev; n != NULL; pprev = &n->next, n = n->next) {
            r = vg_list_entry(n, struct vg_drop_rec, hash);

            if (n->pprev != pprev || drop_hash(c, &r->cidr) != b
                || ++hashed > c->drop_count)
            {
                return -1;
            }
        }
    }

    return listed == c->drop_count && hashed == c->drop_count ? 0 : -1;
}
#endif
