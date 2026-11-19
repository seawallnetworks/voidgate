
/* SPDX-License-Identifier: Apache-2.0 */

#include "policy.h"
#include "log.h"

#include <arpa/inet.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>


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
static void logged_list(char *out, size_t size,
    const struct vg_logged_drop *v, int n);
static void log_drops(struct vg_ctrl *c);
static double tick_dt(struct vg_ctrl *c);
static uint64_t draw_epoch(void);
static struct vg_feed_entry *feed_add(struct vg_ctrl *c, int kind,
    const char *cause);
static void feed_block(struct vg_ctrl *c, int kind, const char *cause,
    const struct vg_drop_rec *r, uint64_t id);
static uint64_t now_ms(void);
static void attack_start(struct vg_ctrl *c);
static void attack_end(struct vg_ctrl *c, int how, uint64_t end_ms);
static void syn_engage(struct vg_ctrl *c);
static void syn_feed(struct vg_ctrl *c, int kind, const char *cause);
static double syn_fp_est(double per_gen, uint32_t blocks);
static void syn_watch(struct vg_ctrl *c, uint64_t unready);


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

    c->feed = calloc(VG_FEED_SIZE, sizeof(*c->feed));

    if (c->feed == NULL) {
        free(c->drop_pool);
        free(c->drop_heads);
        free(c->snap_pool);
        c->drop_pool = NULL;
        c->drop_heads = NULL;
        c->snap_pool = NULL;
        return -1;
    }

    c->epoch = draw_epoch();

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
    free(c->feed);
    c->feed = NULL;
}


/* Random, so a restarted voidgate's sequence numbers, which start again,
 * are never taken for the old ones; never 0.
 */
static uint64_t
draw_epoch(void)
{
    uint64_t         e = 0;
    struct timespec  ts;

    if (getrandom(&e, sizeof(e), 0) != (ssize_t) sizeof(e)) {
        clock_gettime(CLOCK_REALTIME, &ts);
        e = ((uint64_t) ts.tv_sec << 32) ^ (uint64_t) ts.tv_nsec
            ^ ((uint64_t) getpid() << 16);
    }

    return e != 0 ? e : 1;
}


/* The next change, its source the caller's; cause is copied with its
 * spaces as "-", so it stays one word on the protocol's lines.
 */
static struct vg_feed_entry *
feed_add(struct vg_ctrl *c, int kind, const char *cause)
{
    size_t                 i;
    struct timespec        ts;
    struct vg_feed_entry  *ch;

    if (c->feed == NULL) {
        return NULL;
    }

    ch = &c->feed[++c->seq % VG_FEED_SIZE];
    memset(ch, 0, sizeof(*ch));

    clock_gettime(CLOCK_REALTIME, &ts);
    ch->seq = c->seq;
    ch->time_ms = (uint64_t) ts.tv_sec * 1000
                  + (uint64_t) ts.tv_nsec / 1000000;
    ch->kind = (uint8_t) kind;
    ch->source = (uint8_t) c->caller_source;
    ch->uid = c->caller_uid;

    for (i = 0; cause != NULL && cause[i] != '\0'
                && i < sizeof(ch->cause) - 1; i++)
    {
        ch->cause[i] = cause[i] == ' ' ? '-' : cause[i];
    }

    return ch;
}


/* A block or unblock of r; id is r's (an unblock's is read before the
 * lift clears it).
 */
static void
feed_block(struct vg_ctrl *c, int kind, const char *cause,
    const struct vg_drop_rec *r, uint64_t id)
{
    struct vg_feed_entry  *ch;

    ch = feed_add(c, kind, cause);

    if (ch != NULL) {
        ch->id = id;
        ch->cidr = r->cidr;
        ch->reason = r->reason;
        ch->expires = r->reason == VG_REASON_TIMED ? r->expires : 0;
    }
}


void
vg_ctrl_caller(struct vg_ctrl *c, int source, uint32_t uid)
{
    c->caller_source = source;
    c->caller_uid = source != VG_SOURCE_SELF ? uid : 0;
}


const char *
vg_source_name(int source)
{
    return source == VG_SOURCE_SOCKET ? "socket"
           : source == VG_SOURCE_BAN ? "ban" : "self";
}


const char *
vg_attack_how_name(int how)
{
    return how == VG_ATTACK_DISARM ? "disarm" : "quiet";
}


static uint64_t
now_ms(void)
{
    struct timespec  ts;

    clock_gettime(CLOCK_REALTIME, &ts);

    return (uint64_t) ts.tv_sec * 1000 + (uint64_t) ts.tv_nsec / 1000000;
}


/*
 * An attack starts on this tick's rates (Seawall proposal 0017 §1): the
 * gate is armed already, by the wake threshold or anything else. One at a
 * time; an id from 1 after each start, the feed's epoch telling starts
 * apart.
 */
static void
attack_start(struct vg_ctrl *c)
{
    struct vg_feed_entry  *ch;

    memset(&c->attack, 0, sizeof(c->attack));
    c->attack.id = ++c->attack_ids;
    c->attack.start_ms = now_ms();
    c->attack.pps = (uint64_t) c->wake_rx_pps;
    c->attack.bps = (uint64_t) c->wake_rx_bps;
    c->attack_dropped = c->last_m.dropped;
    c->attack_syn_dropped = c->last_m.syn_guard_dropped;
    c->attack_open = 1;

    ch = feed_add(c, VG_FEED_ATTACK, NULL);

    /* one start everywhere: the entry's time, status' attack_since and the
     * end's start, which sw_logd matches (Seawall proposal 0017 §3)
     */
    if (ch != NULL) {
        c->attack.start_ms = ch->time_ms;
        ch->attack = c->attack;
    }

    sw_log_info("attack %llu started: %.0f pps, %.1f Mbps without the "
                "host's own replies", (unsigned long long) c->attack.id,
                c->wake_rx_pps, c->wake_rx_bps / 1e6);
}


/* The open attack ends: its summary to the feed, and kept for status. */
static void
attack_end(struct vg_ctrl *c, int how, uint64_t end_ms)
{
    struct vg_feed_entry  *ch;

    if (!c->attack_open) {
        return;
    }

    c->attack.end_ms = end_ms > c->attack.start_ms ? end_ms
                                                   : c->attack.start_ms;
    c->attack.how = (uint8_t) how;
    c->attack.dropped = c->last_m.dropped >= c->attack_dropped
                        ? c->last_m.dropped - c->attack_dropped : 0;
    c->attack.syn_dropped =
        c->last_m.syn_guard_dropped >= c->attack_syn_dropped
        ? c->last_m.syn_guard_dropped - c->attack_syn_dropped : 0;
    c->attack_open = 0;
    c->last_attack = c->attack;
    c->have_last_attack = 1;

    ch = feed_add(c, VG_FEED_ATTACK_END, vg_attack_how_name(how));

    if (ch != NULL) {
        ch->attack = c->attack;
    }

    sw_log_info("attack %llu ended (%s) after %llu s: peak %llu pps, "
                "%llu dropped, %llu of them first SYNs, %u cut, %u bans",
                (unsigned long long) c->attack.id, vg_attack_how_name(how),
                (unsigned long long) (c->attack.end_ms - c->attack.start_ms)
                / 1000, (unsigned long long) c->attack.pps,
                (unsigned long long) c->attack.dropped,
                (unsigned long long) c->attack.syn_dropped, c->attack.cut,
                c->attack.bans);
}


void
vg_ctrl_reloaded(struct vg_ctrl *c)
{
    (void) feed_add(c, VG_FEED_RELOAD, "reload");
}


const struct vg_feed_entry *
vg_ctrl_feed_entry(const struct vg_ctrl *c, uint64_t seq)
{
    const struct vg_feed_entry  *ch;

    if (c->feed == NULL || seq == 0 || seq > c->seq) {
        return NULL;
    }

    ch = &c->feed[seq % VG_FEED_SIZE];

    return ch->seq == seq ? ch : NULL;
}


uint64_t
vg_ctrl_feed_oldest(const struct vg_ctrl *c)
{
    return c->seq >= VG_FEED_SIZE ? c->seq - VG_FEED_SIZE + 1 : 1;
}


/* The page's last record is kept as a hint: the next page starts after it
 * at once while it is still listed, instead of walking from the oldest.
 */
const struct vg_drop_rec *
vg_ctrl_block_after(struct vg_ctrl *c, uint64_t after)
{
    struct vg_list      *l;
    struct vg_drop_rec  *r;

    if (after != 0 && c->page_hint != NULL && c->page_hint->id == after) {
        return vg_ctrl_block_next(c, c->page_hint);
    }

    for (l = c->drop_all.next; l != &c->drop_all; l = l->next) {
        r = vg_list_entry(l, struct vg_drop_rec, all);

        if (r->id > after) {
            return r;
        }
    }

    return NULL;
}


const struct vg_drop_rec *
vg_ctrl_block_next(struct vg_ctrl *c, const struct vg_drop_rec *r)
{
    c->page_hint = (struct vg_drop_rec *) r;

    if (r->all.next == &c->drop_all) {
        return NULL;
    }

    return vg_list_entry(r->all.next, struct vg_drop_rec, all);
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
    c->page_hint = NULL;
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
        sw_log_warn("lift %s: map delete failed: %s", buf, strerror(errno));
        return -1;
    }

    vg_hlist_del(&r->hash);
    vg_list_del(&r->all);
    vg_list_add_tail(&r->all, &c->drop_free);
    c->drop_count--;
    r->id = 0;

    if (c->page_hint == r) {
        c->page_hint = NULL;
    }

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
        sw_log_info("refuse block %s (covers local/allow)", buf);
        return -1;
    }

    /* A ban client's drop arms too, or its blocks would do nothing in an
     * attack; the arm is that client's, cause "ban".
     */
    if (c->state != VG_ACTIVE
        && vg_ctrl_arm(c, c->caller_source == VG_SOURCE_BAN
                          ? "ban" : "manual block") < 0)
    {
        return -1;
    }

    r = drops_find(c, p);
    again = r != NULL;

    if (r == NULL) {
        r = drop_alloc(c);

        /* Summed into one line per tick, by log_drops(): a large attack
         * refuses thousands.
         */
        if (r == NULL) {
            sw_log_debug("block %s refused: block list full", buf);
            c->refused_full++;
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
        r->id = ++c->drop_ids;
        vg_hlist_add_head(&r->hash, &c->drop_heads[drop_hash(c, p)]);
        vg_list_add_tail(&r->all, &c->drop_all);
        c->drop_count++;
        feed_block(c, VG_FEED_BLOCK, NULL, r, r->id);

        /* an operator's blocks are theirs, recorded as blocks */
        if (c->attack_open) {
            if (c->caller_source == VG_SOURCE_BAN) {
                c->attack.bans++;

            } else if (reason == VG_REASON_POLICY
                       || reason == VG_REASON_AGGREGATE)
            {
                c->attack.cut++;
            }
        }

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
            feed_block(c, VG_FEED_BLOCK, NULL, r, r->id);
        }
    }

    sw_log_debug("block %s (%s)%s", buf, vg_reason_name(reason),
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
    uint64_t id;
    struct vg_drop_rec *r = drops_find(c, p);

    log_drops(c);
    vg_cidr_to_str(p, buf, sizeof(buf));

    if (r != NULL) {
        id = r->id;

        if (drop_remove(c, r) < 0) {
            return -1;
        }

        feed_block(c, VG_FEED_UNBLOCK, "unblock", r, id);

    /* Not listed: still clear a stray map entry. */
    } else if (vg_drop_del(c->maps, p) < 0 && errno != ENOENT) {
        sw_log_warn("unblock: map delete %s failed: %s", buf, strerror(errno));
        return -1;
    }

    sw_log_info("unblock %s", buf);

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
    uint64_t id;
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
        sw_log_warn("reload: unblock %s (now covers local/allow)", buf);

        id = r->id;

        if (drop_remove(c, r) == 0) {
            feed_block(c, VG_FEED_UNBLOCK, "reload", r, id);
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

    if (vg_cfg_commit(c->maps, 1, 0, c->cfg) < 0) {
        sw_log_warn("arm cfg commit failed: %s", strerror(errno));
        return -1;
    }

    c->state = VG_ACTIVE;
    (void) feed_add(c, VG_FEED_ARM, why);

    if (c->caller_source != VG_SOURCE_SELF) {
        sw_log_info("armed (%s, %s uid %u)", why != NULL ? why : "",
                    vg_source_name(c->caller_source), c->caller_uid);

    } else {
        sw_log_info("armed (%s)", why != NULL ? why : "");
    }

    return 0;
}


/*
 * Unarmed first, then the drops flushed: a failed commit changes nothing,
 * so the drop list, and the feed, still say what is in force.
 */
int
vg_ctrl_disarm(struct vg_ctrl *c, const char *why)
{
    log_drops(c);

    if (vg_cfg_commit(c->maps, 0, 0, c->cfg) < 0) {
        sw_log_warn("disarm cfg commit failed: %s", strerror(errno));
        return -1;
    }

    /* standby with the gate, in the attack it was engaged in */
    if (c->syn_engaged) {
        c->syn_engaged = 0;
        c->syn_fp_est = 0;
        syn_feed(c, VG_FEED_SYN_STANDBY, "disarm");
        sw_log_info("syn_guard: standby (disarmed)");
    }

    vg_drop_flush(c->maps);
    drops_reset(c);

    /* the attack, if one is open, ends with the gate: now */
    attack_end(c, VG_ATTACK_DISARM, now_ms());

    c->state = VG_IDLE;
    c->quiet_since = 0;
    (void) feed_add(c, VG_FEED_DISARM, why);

    if (c->caller_source != VG_SOURCE_SELF) {
        sw_log_info("disarmed (%s, %s uid %u)", why != NULL ? why : "",
                    vg_source_name(c->caller_source), c->caller_uid);

    } else {
        sw_log_info("disarmed (%s)", why != NULL ? why : "");
    }

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
    uint64_t id;
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
        id = r->id;

        if (drop_remove(c, r) < 0) {
            continue;
        }

        feed_block(c, VG_FEED_UNBLOCK, "expired", r, id);

        if (sw_log_enabled(SW_LOG_DEBUG)) {
            vg_cidr_to_str(&r->cidr, buf, sizeof(buf));
            sw_log_debug("expire %s (%s)", buf, vg_reason_name(r->reason));
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
        sw_log_info("expired %d blocks (policy %d, aggregate %d, timed %d), "
                    "first %s; %d left", n, by[VG_REASON_POLICY],
                    by[VG_REASON_AGGREGATE], by[VG_REASON_TIMED], list,
                    c->drop_count);
    }
}


const char *
vg_reason_name(uint32_t reason)
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
                     buf, vg_reason_name(v[i].reason));

        if (w < 0 || (size_t) w >= size - used) {
            break;
        }

        used += (size_t) w;
    }
}


/* One log line per tick for every drop added since the last one, however
 * many: a ban burst can add thousands. It names the first VG_LOG_CIDRS
 * prefixes; -v adds a line per prefix. An unblock, a disarm or a reload
 * lift logs the pending line first, so the log keeps its order and never
 * names a prefix as blocked after it was lifted.
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
        sw_log_info("blocked %d listed prefix%s again; %d listed",
                    c->drops_again, c->drops_again == 1 ? "" : "es",
                    c->drop_count);

    } else if (n > 0) {
        logged_list(list, sizeof(list), c->drops_shown, c->drops_shown_n);

        if (n <= VG_LOG_CIDRS) {
            sw_log_info("blocked %s; %s%d listed", list, again, c->drop_count);

        } else {
            sw_log_info("blocked %d prefixes (manual %d, policy %d, "
                        "aggregate %d, timed %d), first %s; %s%d listed", n,
                        c->drops_new[VG_REASON_MANUAL],
                        c->drops_new[VG_REASON_POLICY],
                        c->drops_new[VG_REASON_AGGREGATE],
                        c->drops_new[VG_REASON_TIMED], list, again,
                        c->drop_count);
        }
    }

    if (c->refused_full > 0) {
        sw_log_warn("refused %d block%s: block list full (%u)", c->refused_full,
                    c->refused_full == 1 ? "" : "s", c->drop_pool_cap);
    }

    memset(c->drops_new, 0, sizeof(c->drops_new));
    c->drops_again = 0;
    c->drops_shown_n = 0;
    c->refused_full = 0;
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
        uint64_t drp = m.rx_reply_pkts >= c->last_m.rx_reply_pkts
                       ? m.rx_reply_pkts - c->last_m.rx_reply_pkts : 0;
        uint64_t drb = m.rx_reply_bytes >= c->last_m.rx_reply_bytes
                       ? m.rx_reply_bytes - c->last_m.rx_reply_bytes : 0;
        uint64_t dsyn = m.syn_unproven >= c->last_m.syn_unproven
                        ? m.syn_unproven - c->last_m.syn_unproven : 0;
        uint64_t dsd = m.syn_guard_dropped >= c->last_m.syn_guard_dropped
                       ? m.syn_guard_dropped - c->last_m.syn_guard_dropped
                       : 0;
        uint64_t dsu = m.syn_guard_unready >= c->last_m.syn_guard_unready
                       ? m.syn_guard_unready - c->last_m.syn_guard_unready
                       : 0;

        c->rx_pps = (double) dp / dt;
        c->rx_bps = (double) db * 8.0 / dt;
        drop_pps = (double) dd / dt;

        /* the host's own downloads don't wake the gate, nor keep it
         * from going quiet (Seawall proposal 0017 §1)
         */
        c->wake_rx_pps = (double) (dp > drp ? dp - drp : 0) / dt;
        c->wake_rx_bps = (double) (db > drb ? db - drb : 0) * 8.0 / dt;
        c->syn_pps = (double) dsyn / dt;
        c->syn_drop_pps = (double) dsd / dt;
        syn_watch(c, dsu);
    }

    c->last_m = m;
    c->have_last_m = 1;

    if (dt <= 0) {
        return 0;
    }

    if (c->state == VG_IDLE) {
        vg_vvlog("tick %-6s rx(pps)=%-8.0f rx(Mbps)=%-6.1f "
                 "wake_rx(pps)=%-8.0f wake_rx(Mbps)=%-6.1f",
                 "idle", c->rx_pps, c->rx_bps / 1e6,
                 c->wake_rx_pps, c->wake_rx_bps / 1e6);

        if (c->wake_rx_pps > (double) c->cfg->wake_pps
            || c->wake_rx_bps > (double) c->cfg->wake_mbps * 1000000.0)
        {
            if (vg_ctrl_arm(c, "wake threshold") == 0) {
                attack_start(c);
            }
        }

        return 0;
    }

    walk_remotes(c, dt);
    expire_drops(c);

    sw_log_debug("tick %-6s rx(pps)=%-8.0f rx(Mbps)=%-6.1f "
                 "wake_rx(pps)=%-8.0f dropped(pps)=%-8.0f blocked=%d",
                 "active", c->rx_pps, c->rx_bps / 1e6, c->wake_rx_pps,
                 drop_pps, c->drop_count);

    if (c->attack_open) {
        if ((uint64_t) c->wake_rx_pps > c->attack.pps) {
            c->attack.pps = (uint64_t) c->wake_rx_pps;
        }

        if ((uint64_t) c->wake_rx_bps > c->attack.bps) {
            c->attack.bps = (uint64_t) c->wake_rx_bps;
        }
    }

    if (c->wake_rx_pps < (double) c->cfg->wake_pps
        && c->wake_rx_bps < (double) c->cfg->wake_mbps * 1000000.0)
    {
        if (c->quiet_since == 0) {
            c->quiet_since = time(NULL);
        }

        /* first-SYN drop's standby, in the attack it was engaged in */
        syn_engage(c);

        /* the attack ended when traffic fell, before the disarm, which
         * may come on this tick too (Seawall proposal 0017 §1)
         */
        if (c->attack_open
            && time(NULL) - c->quiet_since >= c->cfg->clear_seconds)
        {
            attack_end(c, VG_ATTACK_QUIET, (uint64_t) c->quiet_since * 1000);
        }

        if (c->drop_count == 0
            && time(NULL) - c->quiet_since >= c->cfg->clear_seconds)
        {
            vg_ctrl_disarm(c, "attack cleared");
        }

    } else {
        c->quiet_since = 0;

        /* over the threshold on a gate armed already: an attack too, on
         * the test that wakes an idle one
         */
        if (!c->attack_open
            && (c->wake_rx_pps > (double) c->cfg->wake_pps
                || c->wake_rx_bps > (double) c->cfg->wake_mbps * 1000000.0))
        {
            attack_start(c);
        }

        /* engaged in the attack that started on this tick */
        syn_engage(c);
    }

    return 0;
}


/*
 * First-SYN drop engages when SYNs from unproven addresses alone, counted
 * before the filter, were over wake_pps on the last tick, whatever armed
 * the gate; it returns to standby after clear_seconds below it (Seawall
 * proposal 0023 §1). Counted before the filter, its own drops keep it
 * engaged, so it doesn't go back and forth.
 */
static void
syn_engage(struct vg_ctrl *c)
{
    time_t now = time(NULL);
    int on = c->syn_engaged;

    if (c->maps == NULL || c->maps->syn == NULL) {
        return;
    }

    if (c->syn_pps > (double) c->cfg->wake_pps) {
        c->syn_quiet_since = 0;
        on = 1;

    } else if (on) {
        if (c->syn_quiet_since == 0) {
            c->syn_quiet_since = now;
        }

        if (now - c->syn_quiet_since >= c->cfg->clear_seconds) {
            on = 0;
        }
    }

    if (on == c->syn_engaged) {
        return;
    }

    if (vg_cfg_commit(c->maps, 1, (uint32_t) on, c->cfg) < 0) {
        sw_log_warn("syn_guard cfg commit failed: %s", strerror(errno));
        return;
    }

    c->syn_engaged = on;
    c->syn_quiet_since = 0;
    c->syn_fp_est = 0;
    c->syn_fp_warned = 0;

    if (on) {
        syn_feed(c, VG_FEED_SYN_ENGAGE, NULL);
        sw_log_info("syn_guard: engaged, %.0f SYNs/s from unproven "
                    "addresses", c->syn_pps);

    } else {
        syn_feed(c, VG_FEED_SYN_STANDBY, "quiet");
        sw_log_info("syn_guard: standby");
    }
}


/* An engage or standby on the feed: the open attack's id, 0 if none,
 * and the tick's SYNs from unproven addresses a second.
 */
static void
syn_feed(struct vg_ctrl *c, int kind, const char *cause)
{
    struct vg_feed_entry  *ch;

    ch = feed_add(c, kind, cause);

    if (ch != NULL) {
        ch->attack.id = c->attack_open ? c->attack.id : 0;
        ch->attack.pps = (uint64_t) c->syn_pps;
    }
}


/*
 * Engaged, the estimated false-pass rate (Seawall proposal 0023 §6):
 * a SYN never seen passes when its 3 bits are all set in one of the 4
 * older generations. Each holds the first SYNs written in 0.9 s, per_gen
 * of them, over blocks of 512 bits: a block holds j of them with the
 * Poisson chance of j at per_gen / blocks, and j keys set a bit with
 * 1 - (1 - 1/512)^3j. Over 1% in a tick, a warning once a spell: more
 * syn_guard_bits. Not engaged, nothing is written: 0.
 */
static void
syn_watch(struct vg_ctrl *c, uint64_t unready)
{
    time_t    now = time(NULL);
    uint32_t  blocks;

    /* logged once a VG_SYN_UNREADY_SHOW, while status shows it */
    if (unready > 0) {
        if (now - c->syn_unready_at >= VG_SYN_UNREADY_SHOW) {
            sw_log_warn("syn_guard: %llu SYNs passed unfiltered: the "
                        "thread that clears the filter is late",
                        (unsigned long long) unready);
        }

        c->syn_unready = unready;
        c->syn_unready_at = now;
    }

    if (!c->syn_engaged) {
        c->syn_fp_est = 0;
        return;
    }

    blocks = 1U << (c->cfg->syn_guard_bits - VG_SYN_BLOCK_LOG2);
    c->syn_fp_est = syn_fp_est(c->syn_drop_pps * VG_SYN_GEN_NS / 1e9,
                               blocks);

    if (c->syn_fp_est > VG_SYN_FP_WARN && !c->syn_fp_warned) {
        c->syn_fp_warned = 1;
        sw_log_warn("syn_guard: an estimated %.1f%% of spoofed SYNs pass "
                    "as retransmissions; raise syn_guard_bits (now %d)",
                    c->syn_fp_est * 100, c->cfg->syn_guard_bits);
    }
}


static double
syn_fp_est(double per_gen, uint32_t blocks)
{
    double lambda = per_gen / blocks, lo, hi, j, p = 0, pj;

    if (lambda <= 0) {
        return 0;
    }

    /* the Poisson terms that matter: around lambda, in logs, which
     * exp(-lambda) alone would underflow past 745
     */
    lo = floor(lambda - 12 * sqrt(lambda) - 30);
    hi = ceil(lambda + 12 * sqrt(lambda) + 30);

    for (j = lo > 0 ? lo : 0; j <= hi; j++) {
        pj = exp(j * log(lambda) - lambda - lgamma(j + 1));
        p += pj * pow(1 - pow(1 - 1.0 / VG_SYN_BLOCK_BITS, 3 * j), 3);
    }

    return 1 - pow(1 - p, VG_SYN_OLDER);
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
