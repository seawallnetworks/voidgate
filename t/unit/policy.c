
/* SPDX-License-Identifier: Apache-2.0 */

#include "policy.h"
#include "ipaddr.h"
#include "log.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>


static void set_v4_item(int i, uint32_t id, uint64_t pkts);
static void force_dt(struct vg_ctrl *c);
static int tick(struct vg_ctrl *c);
static struct vg_drop_rec *nth(struct vg_ctrl *c, int k);
static void age_all(struct vg_ctrl *c, time_t expires, int policy_too);
static void test_ttl(void);
static void test_drop_index(void);
static void test_del_fail(void);
static void test_expire_log(void);
static void test_drop_log(void);
static void test_pool(void);
static void test_feed(void);
static void test_feed_wrap(void);
static void test_feed_ban(void);
static void test_wake_replies(void);
static void test_attacks(void);
static void test_blocks_pages(void);
static struct vg_cidr v4(int a, int b, int c, int d, int len);
static int log_count(const char *path, const char *needle);
static int log_line_of(const char *path, const char *needle);
static int log_start(char *path);
static void log_stop(int saved);

#define FOREACH_MAX  64

static struct vg_cidr deleted;
static int deleted_count;
static int del_fail;        /* vg_drop_del fails with EIO */
static int add_fail;        /* vg_drop_add fails with ENOSPC */
static int commit_fail;     /* vg_cfg_commit fails with EIO */
static int complete_scan = 1;
static int nitems;
static struct {
    int                   family;
    uint8_t               addr[16];
    struct host_counters  c;
} items[FOREACH_MAX];

int
vg_drop_del(struct vg_maps *m, const struct vg_cidr *p)
{
    (void) m;

    if (del_fail) {
        errno = EIO;
        return -1;
    }

    deleted = *p;
    deleted_count++;

    return 0;
}


int
vg_drop_add(struct vg_maps *m, const struct vg_cidr *p, uint32_t reason,
    uint32_t now)
{
    (void) m;

    if (add_fail) {
        errno = ENOSPC;
        return -1;
    }

    (void) p;
    (void) reason;
    (void) now;

    return 0;
}


int
vg_cfg_commit(struct vg_maps *m, uint32_t armed,
    const struct vg_config *cfg)
{
    (void) m;
    (void) armed;
    (void) cfg;

    if (commit_fail) {
        errno = EIO;
        return -1;
    }

    return 0;
}


int
vg_drop_flush(struct vg_maps *m)
{
    (void) m;

    return 0;
}


int
vg_populate_allow(struct vg_maps *m, const struct vg_config *cfg)
{
    (void) m;
    (void) cfg;

    return 0;
}


int
vg_populate_local(struct vg_maps *m, const struct vg_config *cfg)
{
    (void) m;
    (void) cfg;

    return 0;
}


/* What the data path's counters read: 0, unless a test sets them. */
static struct vg_metrics  stub_metrics;


int
vg_metrics_read(struct vg_maps *m, struct vg_metrics *out)
{
    (void) m;
    *out = stub_metrics;

    return 0;
}


int
vg_remote_foreach(struct vg_maps *m, uint32_t budget, vg_remote_pt fn,
    void *ctx)
{
    int i;

    (void) m;
    (void) budget;

    for (i = 0; i < nitems; i++) {
        fn(items[i].family, items[i].addr, &items[i].c, ctx);
    }

    return complete_scan;
}


static void
set_v4_item(int i, uint32_t id, uint64_t pkts)
{
    memset(&items[i], 0, sizeof(items[i]));
    items[i].family = AF_INET;
    memcpy(items[i].addr, &id, sizeof(id));
    items[i].c.in_pkts = pkts;
}


static void
force_dt(struct vg_ctrl *c)
{
    clock_gettime(CLOCK_MONOTONIC, &c->last_tick);
    c->last_tick.tv_sec -= 1;
    c->have_last_tick = 1;
    c->have_last_m = 1;
}


static int
tick(struct vg_ctrl *c)
{
    force_dt(c);

    return vg_ctrl_tick(c);
}


/* The k-th listed drop, oldest first. */
static struct vg_drop_rec *
nth(struct vg_ctrl *c, int k)
{
    struct vg_list *l = c->drop_all.next;

    while (k-- > 0) {
        assert(l != &c->drop_all);
        l = l->next;
    }

    assert(l != &c->drop_all);

    return vg_list_entry(l, struct vg_drop_rec, all);
}


/* Set every listed drop's expires; policy_too also ages policy and
 * aggregate drops past ban_time.
 */
static void
age_all(struct vg_ctrl *c, time_t expires, int policy_too)
{
    struct vg_list *l;
    struct vg_drop_rec *r;

    for (l = c->drop_all.next; l != &c->drop_all; l = l->next) {
        r = vg_list_entry(l, struct vg_drop_rec, all);
        r->expires = expires;

        if (policy_too) {
            r->inserted = 0;
        }
    }
}


/* drop <cidr> ttl=N: lifts at its own expiry, merges with other drops of
 * the same prefix, and does not feed aggregate_k.
 */
static void
test_ttl(void)
{
    struct vg_config cfg;
    struct vg_ctrl c;
    struct vg_cidr a, b, m;
    time_t now = time(NULL);
    int i;

    vg_config_defaults(&cfg);
    cfg.remote_map_size = 16;
    cfg.wake_pps = 0;
    cfg.wake_mbps = 0;
    cfg.aggregate_k = 2;
    nitems = 0;
    complete_scan = 1;
    assert(vg_ctrl_init(&c, &cfg, NULL, NULL, NULL) == 0);

    /* A ttl drop arms the gate like a manual one. */
    assert(vg_parse_cidr("198.18.0.1/32", &a) == 0);
    assert(vg_parse_cidr("2001:db8::1/128", &b) == 0);
    assert(vg_ctrl_drop_ttl(&c, &a, 60) == 0);
    assert(c.state == VG_ACTIVE);
    assert(vg_ctrl_drop_ttl(&c, &b, 60) == 0);
    assert(c.drop_count == 2 && nth(&c, 0)->reason == VG_REASON_TIMED);
    assert(nth(&c, 0)->expires >= now + 60);

    /* A shorter re-ban does not shorten it; a longer one extends it. */
    assert(vg_ctrl_drop_ttl(&c, &a, 10) == 0);
    assert(nth(&c, 0)->expires >= now + 60);
    assert(vg_ctrl_drop_ttl(&c, &a, 600) == 0);
    assert(nth(&c, 0)->expires >= now + 600);

    /* Not expired: kept. Expired: lifted, v4 and v6 alike. */
    assert(tick(&c) == 0);
    assert(c.drop_count == 2);
    age_all(&c, now - 1, 0);
    assert(tick(&c) == 0);
    assert(c.drop_count == 0);

    /* Manual wins: a ttl drop does not downgrade it, a manual one
     * upgrades a ttl drop to permanent. */
    assert(vg_parse_cidr("198.18.1.0/24", &m) == 0);
    assert(vg_ctrl_drop(&c, &m, VG_REASON_MANUAL) == 0);
    assert(vg_ctrl_drop_ttl(&c, &m, 1) == 0);
    assert(nth(&c, 0)->reason == VG_REASON_MANUAL);
    assert(vg_ctrl_drop_ttl(&c, &a, 1) == 0);
    assert(vg_ctrl_drop(&c, &a, VG_REASON_MANUAL) == 0);
    assert(nth(&c, 1)->reason == VG_REASON_MANUAL);
    nth(&c, 1)->expires = now - 1;
    assert(tick(&c) == 0);
    assert(c.drop_count == 2);
    assert(vg_ctrl_undrop(&c, &m) == 0 && vg_ctrl_undrop(&c, &a) == 0);

    /* A ttl drop on a policy drop keeps at least the policy ban_time. */
    assert(vg_ctrl_drop(&c, &a, VG_REASON_POLICY) == 0);
    assert(vg_ctrl_drop_ttl(&c, &a, 1) == 0);
    assert(nth(&c, 0)->reason == VG_REASON_TIMED);
    assert(nth(&c, 0)->expires >= now + cfg.ban_time);
    assert(vg_ctrl_undrop(&c, &a) == 0);

    /* Ttl bans in one /24 do not count toward aggregate_k (2 here): the
     * policy drop of a third host there does not drop the /24. */
    assert(vg_parse_cidr("198.18.2.1/32", &a) == 0);
    assert(vg_ctrl_drop_ttl(&c, &a, 60) == 0);
    assert(vg_parse_cidr("198.18.2.2/32", &a) == 0);
    assert(vg_ctrl_drop_ttl(&c, &a, 60) == 0);
    nitems = 1;
    set_v4_item(0, htonl(0xc6120203), 1);  /* 198.18.2.3 */
    assert(tick(&c) == 0);
    items[0].c.in_pkts += cfg.threshold_pps + 1;
    assert(tick(&c) == 0);
    assert(c.drop_count == 3);

    for (i = 0; i < c.drop_count; i++) {
        assert(nth(&c, i)->cidr.prefixlen == 32);
    }

    /* Disarm flushes ttl drops too. */
    assert(vg_ctrl_disarm(&c, "test") == 0);
    assert(c.drop_count == 0);
    nitems = 0;
    vg_ctrl_free(&c);
}


/* Mixed adds, re-adds, undrops and expiries over a pool that shares
 * buckets (v4 /32 and /24 on the same address, v6): after every step the
 * hash index matches the array and lookups match a shadow set.
 */
#define POOL  3000

static void
test_drop_index(void)
{
    static struct vg_cidr pool[POOL];
    static unsigned char listed[POOL];
    struct vg_config cfg;
    struct vg_ctrl c;
    unsigned seed = 12345;
    time_t now = time(NULL);
    struct vg_drop_rec *r;
    int i, k, step;

    vg_config_defaults(&cfg);
    cfg.remote_map_size = 16;
    cfg.drop_map_size = 1024;   /* fewest buckets: chains get exercised */
    cfg.wake_pps = 0;
    cfg.wake_mbps = 0;
    nitems = 0;
    assert(vg_ctrl_init(&c, &cfg, NULL, NULL, NULL) == 0);
    assert(c.drop_nbuckets == 2048 && c.drop_pool_cap == 2048);

    for (i = 0; i < POOL; i++) {
        memset(&pool[i], 0, sizeof(pool[i]));

        if (i % 3 == 2) {
            pool[i].family = AF_INET6;
            pool[i].prefixlen = 128;
            pool[i].addr[0] = 0x20;
            pool[i].addr[1] = 0x01;
            pool[i].addr[2] = 0x0d;
            pool[i].addr[3] = 0xb8;
            pool[i].addr[14] = (uint8_t) (i >> 8);
            pool[i].addr[15] = (uint8_t) i;

        } else {
            pool[i].family = AF_INET;
            pool[i].prefixlen = i % 3 == 0 ? 32 : 24;
            pool[i].addr[0] = 10;
            pool[i].addr[1] = (uint8_t) (i >> 8);
            pool[i].addr[2] = (uint8_t) i;
            vg_cidr_mask(&pool[i]);
        }
    }

    for (step = 0; step < 20000; step++) {
        seed = seed * 1103515245u + 12345u;
        k = (int) ((seed >> 8) % POOL);

        switch ((seed >> 4) % 8) {
        case 0: case 1: case 2:
            assert(vg_ctrl_drop_ttl(&c, &pool[k], 600) == 0);
            listed[k] = 1;
            break;
        case 3:
            assert(vg_ctrl_drop(&c, &pool[k], VG_REASON_POLICY) == 0);
            listed[k] = 1;
            break;
        case 4:
            assert(vg_ctrl_drop(&c, &pool[k], VG_REASON_MANUAL) == 0);
            listed[k] = 1;
            break;
        case 5: case 6:
            assert(vg_ctrl_undrop(&c, &pool[k]) == 0);
            listed[k] = 0;
            break;
        default:
            /* Expire every non-manual drop in this pool slice. */
            age_all(&c, now - 1, 1);

            assert(tick(&c) == 0);

            for (i = 0; i < POOL; i++) {
                r = vg_ctrl_drops_find(&c, &pool[i]);
                listed[i] = r != NULL && r->reason == VG_REASON_MANUAL;
            }

            for (i = 0; i < c.drop_count; i++) {
                assert(nth(&c, i)->reason == VG_REASON_MANUAL);
            }
        }

        assert(vg_ctrl_drops_check(&c) == 0);

        if (step % 500 == 0) {
            for (i = 0; i < POOL; i++) {
                assert((vg_ctrl_drops_find(&c, &pool[i]) != NULL) == listed[i]);
            }
        }
    }

    /* Disarm empties the index too. */
    assert(vg_ctrl_disarm(&c, "test") == 0);
    assert(vg_ctrl_drops_check(&c) == 0);

    for (i = 0; i < POOL; i++) {
        assert(vg_ctrl_drops_find(&c, &pool[i]) == NULL);
    }

    vg_ctrl_free(&c);
}


/* A failed map delete keeps the record listed and indexed, so the prefix
 * is still tracked (not dropping untracked) and the next pass retries.
 */
static void
test_del_fail(void)
{
    struct vg_config cfg;
    struct vg_ctrl c;
    struct vg_cidr a, b;
    time_t now = time(NULL);

    vg_config_defaults(&cfg);
    cfg.remote_map_size = 16;
    cfg.wake_pps = 0;
    cfg.wake_mbps = 0;
    nitems = 0;
    assert(vg_ctrl_init(&c, &cfg, NULL, NULL, NULL) == 0);
    assert(vg_parse_cidr("198.18.7.1/32", &a) == 0);
    assert(vg_parse_cidr("198.18.7.2/32", &b) == 0);
    assert(vg_ctrl_drop_ttl(&c, &a, 60) == 0);
    assert(vg_ctrl_drop_ttl(&c, &b, 60) == 0);

    del_fail = 1;
    assert(vg_ctrl_undrop(&c, &a) < 0);
    assert(c.drop_count == 2 && vg_ctrl_drops_find(&c, &a) != NULL);

    /* Expiry skips the failing slot and does not spin on it. */
    age_all(&c, now - 1, 0);
    assert(tick(&c) == 0);
    assert(c.drop_count == 2 && vg_ctrl_drops_check(&c) == 0);

    del_fail = 0;
    assert(tick(&c) == 0);
    assert(c.drop_count == 0 && vg_ctrl_drops_check(&c) == 0);

    vg_ctrl_free(&c);
}


/* Lines of path containing needle. */
static int
log_count(const char *path, const char *needle)
{
    FILE *fp = fopen(path, "r");
    char line[2048];    /* a summary names up to VG_LOG_CIDRS prefixes */
    int n = 0;

    assert(fp != NULL);

    while (fgets(line, sizeof(line), fp) != NULL) {
        n += strstr(line, needle) != NULL;
    }

    fclose(fp);

    return n;
}


/* 1-based line of the first match, or 0. */
static int
log_line_of(const char *path, const char *needle)
{
    FILE *fp = fopen(path, "r");
    char line[2048];
    int n = 0;

    assert(fp != NULL);

    while (fgets(line, sizeof(line), fp) != NULL) {
        n++;

        if (strstr(line, needle) != NULL) {
            fclose(fp);
            return n;
        }
    }

    fclose(fp);

    return 0;
}


/* Send stderr (the daemon log) to a new temp file at path; returns the old
 * stderr for log_stop.
 */
static int
log_start(char *path)
{
    int fd, saved;

    fd = mkstemp(path);
    assert(fd >= 0);
    fflush(stderr);
    saved = dup(2);
    assert(saved >= 0 && dup2(fd, 2) == 2);
    close(fd);

    return saved;
}


static void
log_stop(int saved)
{
    fflush(stderr);
    assert(dup2(saved, 2) == 2);
    close(saved);
}


/* Many drops expiring in one tick log one summary line, not one per
 * prefix; -v adds the per-prefix lines.
 */
static void
test_expire_log(void)
{
    struct vg_config cfg;
    struct vg_ctrl c;
    struct vg_cidr p;
    char path[32];
    time_t now = time(NULL);
    int saved, i, verbose;

    vg_config_defaults(&cfg);
    cfg.remote_map_size = 16;
    cfg.wake_pps = 0;
    cfg.wake_mbps = 0;
    nitems = 0;

    for (verbose = 0; verbose <= 1; verbose++) {
        assert(vg_ctrl_init(&c, &cfg, NULL, NULL, NULL) == 0);

        for (i = 1; i <= 3; i++) {
            memset(&p, 0, sizeof(p));
            p.family = AF_INET;
            p.prefixlen = 32;
            p.addr[0] = 198;
            p.addr[1] = 18;
            p.addr[2] = 9;
            p.addr[3] = (uint8_t) i;
            assert(vg_ctrl_drop_ttl(&c, &p, 60) == 0);
        }

        assert(vg_ctrl_drop(&c, &p, VG_REASON_POLICY) == 0);  /* stays timed */
        p.addr[3] = 4;
        assert(vg_ctrl_drop(&c, &p, VG_REASON_POLICY) == 0);
        assert(tick(&c) == 0);              /* logs the drops, not here */
        nth(&c, 3)->inserted = 0;           /* policy, past ban_time */
        age_all(&c, now - 1, 0);

        snprintf(path, sizeof(path), "/tmp/vg-expire-log-XXXXXX");
        saved = log_start(path);
        sw_log_set_level(verbose ? SW_LOG_DEBUG : SW_LOG_INFO);

        assert(tick(&c) == 0);

        sw_log_set_level(SW_LOG_INFO);
        log_stop(saved);

        assert(c.drop_count == 0);
        assert(log_count(path, "expired 198.18.9.1/32 (timed), "
                               "198.18.9.2/32 (timed), 198.18.9.3/32 (timed), "
                               "198.18.9.4/32 (policy); 0 left") == 1);
        assert(log_count(path, "expired") == 1);
        assert(log_count(path, "unblock") == 0);
        assert(log_count(path, "expire 198.18.9.") == (verbose ? 4 : 0));

        unlink(path);
        vg_ctrl_free(&c);
    }
}


/* Drops added between ticks log one summary line on the next tick, not one
 * per prefix; a refusal still logs its own line; -v adds the per-prefix
 * lines, re-drops included.
 */
static void
test_drop_log(void)
{
    struct vg_config cfg;
    struct vg_ctrl c;
    struct vg_cidr p, meta;
    char path[32];
    int saved, i, verbose;

    vg_config_defaults(&cfg);
    cfg.remote_map_size = 16;
    cfg.wake_pps = 0;
    cfg.wake_mbps = 0;
    nitems = 0;
    assert(vg_parse_cidr("169.254.169.254/32", &meta) == 0);

    for (verbose = 0; verbose <= 1; verbose++) {
        assert(vg_ctrl_init(&c, &cfg, NULL, NULL, NULL) == 0);
        snprintf(path, sizeof(path), "/tmp/vg-drop-log-XXXXXX");
        saved = log_start(path);
        sw_log_set_level(verbose ? SW_LOG_DEBUG : SW_LOG_INFO);

        memset(&p, 0, sizeof(p));
        p.family = AF_INET;
        p.prefixlen = 32;
        p.addr[0] = 198;
        p.addr[1] = 18;
        p.addr[2] = 10;

        for (i = 1; i <= 3; i++) {                      /* 3 new, timed */
            p.addr[3] = (uint8_t) i;
            assert(vg_ctrl_drop_ttl(&c, &p, 60) == 0);
        }

        assert(vg_ctrl_drop_ttl(&c, &p, 600) == 0);     /* .3 again */
        p.addr[3] = 4;
        assert(vg_ctrl_drop(&c, &p, VG_REASON_POLICY) == 0);  /* 1 new */
        assert(vg_ctrl_drop_ttl(&c, &meta, 60) < 0);    /* refused */
        assert(tick(&c) == 0);
        assert(tick(&c) == 0);                          /* nothing new */

        sw_log_set_level(SW_LOG_INFO);
        log_stop(saved);

        assert(log_count(path, "blocked 198.18.10.1/32 (timed), "
                               "198.18.10.2/32 (timed), 198.18.10.3/32 (timed), "
                               "198.18.10.4/32 (policy); 1 again, 4 listed")
               == 1);
        assert(log_count(path, "[INFO] blocked ") == 1);
        assert(log_count(path, "refuse block 169.254.169.254/32") == 1);
        assert(log_count(path, "block 198.18.10.") == (verbose ? 5 : 0));
        assert(log_count(path, "block 198.18.10.3/32 (timed) again")
               == verbose);

        unlink(path);
        vg_ctrl_free(&c);
    }
}


/* Past VG_LOG_CIDRS new drops in a tick, the line counts them by reason
 * and names only the first ones; a tick of re-drops alone says so.
 */
static void
test_drop_log_burst(void)
{
    struct vg_config cfg;
    struct vg_ctrl c;
    struct vg_cidr p;
    char path[32];
    int saved, i, round;

    vg_config_defaults(&cfg);
    cfg.remote_map_size = 16;
    cfg.wake_pps = 0;
    cfg.wake_mbps = 0;
    nitems = 0;
    assert(vg_ctrl_init(&c, &cfg, NULL, NULL, NULL) == 0);
    snprintf(path, sizeof(path), "/tmp/vg-burst-log-XXXXXX");
    saved = log_start(path);

    memset(&p, 0, sizeof(p));
    p.family = AF_INET;
    p.prefixlen = 32;
    p.addr[0] = 198;
    p.addr[1] = 18;
    p.addr[2] = 11;

    for (round = 0; round < 2; round++) {           /* new, then again */
        for (i = 1; i <= VG_LOG_CIDRS + 2; i++) {
            p.addr[3] = (uint8_t) i;
            assert(vg_ctrl_drop_ttl(&c, &p, 60) == 0);
        }

        assert(tick(&c) == 0);
    }

    log_stop(saved);

    assert(log_count(path, "blocked 10 prefixes (manual 0, policy 0, "
                           "aggregate 0, timed 10), first 198.18.11.1/32 "
                           "(timed), ") == 1);
    assert(log_count(path, "198.18.11.8/32 (timed); 10 listed") == 1);
    assert(log_count(path, "198.18.11.9/32") == 0);
    assert(log_count(path, "blocked 10 listed prefixes again; 10 listed")
           == 1);

    unlink(path);
    vg_ctrl_free(&c);
}


/* An unblock or disarm before the tick logs the pending blocks first: the
 * log reads in order, and the tick does not name a lifted prefix.
 */
static void
test_drop_log_order(void)
{
    struct vg_config cfg;
    struct vg_ctrl c;
    struct vg_cidr a, b;
    char path[32];
    int saved;

    vg_config_defaults(&cfg);
    cfg.remote_map_size = 16;
    cfg.wake_pps = 0;
    cfg.wake_mbps = 0;
    nitems = 0;
    assert(vg_parse_cidr("198.18.12.1/32", &a) == 0);
    assert(vg_parse_cidr("198.18.12.2/32", &b) == 0);
    assert(vg_ctrl_init(&c, &cfg, NULL, NULL, NULL) == 0);
    snprintf(path, sizeof(path), "/tmp/vg-order-log-XXXXXX");
    saved = log_start(path);

    assert(vg_ctrl_drop_ttl(&c, &a, 60) == 0);
    assert(vg_ctrl_undrop(&c, &a) == 0);
    assert(vg_ctrl_drop_ttl(&c, &b, 60) == 0);
    assert(vg_ctrl_disarm(&c, "test") == 0);
    assert(tick(&c) == 0);

    log_stop(saved);

    assert(log_count(path, "blocked 198.18.12.1/32 (timed); 1 listed") == 1);
    assert(log_count(path, "blocked 198.18.12.2/32 (timed); 1 listed") == 1);
    assert(log_count(path, "[INFO] blocked ") == 2);
    assert(log_line_of(path, "blocked 198.18.12.1/32")
           < log_line_of(path, "unblock 198.18.12.1/32"));

    unlink(path);
    vg_ctrl_free(&c);
}


/* Records come from a fixed pool of 2 x drop_map_size (drop_v4 and
 * drop_v6 each hold drop_map_size): full means refused, a lifted record is
 * reused, and a failed map write gives its record back.
 */
static void
test_pool(void)
{
    struct vg_config cfg;
    struct vg_ctrl c;
    struct vg_cidr p[6];
    int i;

    vg_config_defaults(&cfg);
    cfg.remote_map_size = 16;
    cfg.drop_map_size = 2;
    cfg.wake_pps = 0;
    cfg.wake_mbps = 0;
    nitems = 0;
    assert(vg_ctrl_init(&c, &cfg, NULL, NULL, NULL) == 0);
    assert(c.drop_pool_cap == 4);

    for (i = 0; i < 6; i++) {
        memset(&p[i], 0, sizeof(p[i]));
        p[i].family = AF_INET;
        p[i].prefixlen = 32;
        p[i].addr[0] = 198;
        p[i].addr[1] = 18;
        p[i].addr[2] = 11;
        p[i].addr[3] = (uint8_t) i;
    }

    for (i = 0; i < 4; i++) {
        assert(vg_ctrl_drop_ttl(&c, &p[i], 60) == 0);
    }

    assert(vg_ctrl_drop_ttl(&c, &p[4], 60) < 0);           /* full */
    assert(vg_ctrl_drop_ttl(&c, &p[3], 600) == 0);         /* re-drop: ok */
    assert(c.drop_count == 4 && vg_ctrl_drops_check(&c) == 0);

    assert(vg_ctrl_undrop(&c, &p[1]) == 0);
    assert(vg_ctrl_drop_ttl(&c, &p[4], 60) == 0);          /* reuses it */
    assert(c.drop_used == 4 && c.drop_count == 4);
    assert(vg_ctrl_drops_check(&c) == 0);

    /* A failed map write returns the record: nothing leaks. */
    assert(vg_ctrl_undrop(&c, &p[0]) == 0);
    add_fail = 1;
    assert(vg_ctrl_drop_ttl(&c, &p[5], 60) < 0);
    add_fail = 0;
    assert(c.drop_count == 3 && vg_ctrl_drops_find(&c, &p[5]) == NULL);
    assert(vg_ctrl_drop_ttl(&c, &p[5], 60) == 0);
    assert(c.drop_used == 4 && vg_ctrl_drops_check(&c) == 0);

    /* Oldest first: p[2], p[3], p[4], p[5]. */
    for (i = 0; i < 4; i++) {
        assert(memcmp(&nth(&c, i)->cidr, &p[i + 2], sizeof(p[0])) == 0);
    }

    /* Disarm hands the whole pool back. */
    assert(vg_ctrl_disarm(&c, "test") == 0);
    assert(c.drop_used == 0 && c.drop_count == 0);
    assert(vg_ctrl_drops_check(&c) == 0);

    vg_ctrl_free(&c);
}


static struct vg_cidr
v4(int a, int b, int c, int d, int len)
{
    struct vg_cidr  p;

    memset(&p, 0, sizeof(p));
    p.family = AF_INET;
    p.prefixlen = (uint8_t) len;
    p.addr[0] = (uint8_t) a;
    p.addr[1] = (uint8_t) b;
    p.addr[2] = (uint8_t) c;
    p.addr[3] = (uint8_t) d;

    return p;
}


/* The change stream (Seawall proposal 0012 §2): every block, lift, arm,
 * disarm and reload, in order, each the socket caller's or voidgate's own;
 * "block list full" refusals summed per tick.
 */
static void
test_feed(void)
{
    struct vg_config             cfg;
    struct vg_ctrl               c;
    struct vg_cidr               p[6];
    const struct vg_feed_entry  *ch;
    char                         path[32];
    int                          i, saved;
    uint64_t                     s;

    vg_config_defaults(&cfg);
    cfg.remote_map_size = 16;
    cfg.drop_map_size = 2;
    cfg.wake_pps = 0;
    cfg.wake_mbps = 0;
    nitems = 0;
    assert(vg_ctrl_init(&c, &cfg, NULL, NULL, NULL) == 0);
    assert(c.epoch != 0 && c.seq == 0);
    assert(vg_ctrl_feed_entry(&c, 0) == NULL
           && vg_ctrl_feed_entry(&c, 1) == NULL);
    assert(vg_ctrl_feed_oldest(&c) == 1);

    for (i = 0; i < 6; i++) {
        p[i] = v4(198, 18, 12, i, 32);
    }

    /* a socket's drop, the gate idle: the arm is the caller's too */
    vg_ctrl_caller(&c, VG_SOURCE_SOCKET, 1000);
    assert(vg_ctrl_drop(&c, &p[0], VG_REASON_MANUAL) == 0);
    vg_ctrl_caller(&c, VG_SOURCE_SELF, 0);
    assert(c.seq == 2);
    ch = vg_ctrl_feed_entry(&c, 1);
    assert(ch->kind == VG_FEED_ARM && ch->source == VG_SOURCE_SOCKET
           && ch->uid == 1000);
    assert(strcmp(ch->cause, "manual-block") == 0 && ch->time_ms > 0);
    ch = vg_ctrl_feed_entry(&c, 2);
    assert(ch->kind == VG_FEED_BLOCK && ch->source == VG_SOURCE_SOCKET
           && ch->uid == 1000);
    assert(ch->id == 1 && ch->reason == VG_REASON_MANUAL && ch->expires == 0);
    assert(memcmp(&ch->cidr, &p[0], sizeof(p[0])) == 0);

    /* voidgate's own; a timed re-drop that extends is a change, a policy
     * re-drop that changes nothing isn't
     */
    assert(vg_ctrl_drop_ttl(&c, &p[1], 60) == 0);
    ch = vg_ctrl_feed_entry(&c, 3);
    assert(ch->kind == VG_FEED_BLOCK && ch->source == VG_SOURCE_SELF
           && ch->id == 2);
    assert(ch->reason == VG_REASON_TIMED && ch->expires > time(NULL));
    assert(vg_ctrl_drop_ttl(&c, &p[1], 600) == 0);
    ch = vg_ctrl_feed_entry(&c, 4);
    assert(ch->kind == VG_FEED_BLOCK && ch->id == 2);
    assert(ch->expires >= time(NULL) + 599);
    assert(vg_ctrl_drop(&c, &p[0], VG_REASON_POLICY) == 0);
    assert(vg_ctrl_drop(&c, &p[1], VG_REASON_POLICY) == 0);
    assert(c.seq == 4);

    /* full: refusals counted, one line, no change */
    assert(vg_ctrl_drop(&c, &p[2], VG_REASON_POLICY) == 0);
    assert(vg_ctrl_drop(&c, &p[3], VG_REASON_POLICY) == 0);
    assert(c.seq == 6);
    snprintf(path, sizeof(path), "/tmp/vg-feed-log-XXXXXX");
    saved = log_start(path);

    for (i = 0; i < 3; i++) {
        assert(vg_ctrl_drop(&c, &p[4], VG_REASON_POLICY) < 0);
    }

    assert(c.refused_full == 3 && c.seq == 6);

    /* the lift logs the pending lines first */
    vg_ctrl_caller(&c, VG_SOURCE_SOCKET, 0);
    assert(vg_ctrl_undrop(&c, &p[0]) == 0);
    vg_ctrl_caller(&c, VG_SOURCE_SELF, 0);
    log_stop(saved);
    assert(log_count(path, "refused 3 blocks: block list full (4)") == 1);
    assert(log_count(path, "refused:") == 0);
    assert(c.refused_full == 0);
    unlink(path);

    ch = vg_ctrl_feed_entry(&c, 7);
    assert(ch->kind == VG_FEED_UNBLOCK && ch->source == VG_SOURCE_SOCKET && ch->uid == 0);
    assert(strcmp(ch->cause, "unblock") == 0 && ch->id == 1);
    assert(memcmp(&ch->cidr, &p[0], sizeof(p[0])) == 0);

    /* not listed: nothing lifted, no change */
    assert(vg_ctrl_undrop(&c, &p[5]) == 0);
    assert(c.seq == 7);

    /* expiry is voidgate's own: one change per lift */
    age_all(&c, time(NULL) - 1, 1);
    assert(tick(&c) == 0);
    assert(c.drop_count == 0 && c.seq == 10);

    for (s = 8; s <= 10; s++) {
        ch = vg_ctrl_feed_entry(&c, s);
        assert(ch->kind == VG_FEED_UNBLOCK && ch->source == VG_SOURCE_SELF);
        assert(strcmp(ch->cause, "expired") == 0);
    }

    /* a reload's lifts, then the reload; a disarm lifts all in one */
    assert(vg_ctrl_drop(&c, &p[5], VG_REASON_MANUAL) == 0);
    cfg.local_cidr[0] = p[5];
    cfg.local_cidr_count = 1;
    assert(vg_ctrl_prune_protected(&c) == 1);
    vg_ctrl_reloaded(&c);
    assert(vg_ctrl_feed_entry(&c, 12)->kind == VG_FEED_UNBLOCK);
    assert(strcmp(vg_ctrl_feed_entry(&c, 12)->cause, "reload") == 0);
    assert(vg_ctrl_feed_entry(&c, 13)->kind == VG_FEED_RELOAD);
    cfg.local_cidr_count = 0;

    assert(vg_ctrl_drop(&c, &p[4], VG_REASON_POLICY) == 0);

    /* a disarm that can't unarm changes nothing: the drops stay listed,
     * and no change says otherwise
     */
    commit_fail = 1;
    assert(vg_ctrl_disarm(&c, "attack cleared") < 0);
    commit_fail = 0;
    assert(c.state == VG_ACTIVE && c.drop_count == 1 && c.seq == 14);
    assert(vg_ctrl_block_after(&c, 0) != NULL);

    assert(vg_ctrl_disarm(&c, "attack cleared") == 0);
    ch = vg_ctrl_feed_entry(&c, 15);
    assert(ch->kind == VG_FEED_DISARM && ch->source == VG_SOURCE_SELF);
    assert(strcmp(ch->cause, "attack-cleared") == 0);
    assert(c.seq == 15 && vg_ctrl_feed_entry(&c, 16) == NULL);

    vg_ctrl_free(&c);
}


/*
 * Replies to the host's own flows don't wake the gate, nor keep it from
 * going quiet (Seawall proposal 0017 §1): wake_* compare rx less them.
 * Each tick is about a second, its counters stub_metrics's increments.
 */
static void
wake_tick(struct vg_ctrl *c, uint64_t pkts, uint64_t replies)
{
    stub_metrics.rx_pkts += pkts;
    stub_metrics.rx_bytes += pkts * 1500;
    stub_metrics.rx_reply_pkts += replies;
    stub_metrics.rx_reply_bytes += replies * 1500;

    assert(tick(c) == 0);
}


static void
test_wake_replies(void)
{
    struct vg_config  cfg;
    struct vg_ctrl    c;

    vg_config_defaults(&cfg);
    cfg.remote_map_size = 16;
    cfg.wake_pps = 2000;
    cfg.wake_mbps = 1000;
    nitems = 0;
    complete_scan = 1;
    memset(&stub_metrics, 0, sizeof(stub_metrics));
    assert(vg_ctrl_init(&c, &cfg, NULL, NULL, NULL) == 0);
    c.last_m = stub_metrics;

    /* a download: 5000 pps, all but 100 of them replies, stays idle */
    wake_tick(&c, 5000, 4900);
    assert(c.state == VG_IDLE);
    assert(c.rx_pps > 4900 && c.rx_pps < 5100);
    assert(c.wake_rx_pps > 90 && c.wake_rx_pps < 110);

    /* the same rate, 4000 of it not replies, wakes it */
    wake_tick(&c, 5000, 1000);
    assert(c.state == VG_ACTIVE);
    assert(c.wake_rx_pps > 3900 && c.wake_rx_pps < 4100);

    /* armed, a download alone is quiet; the flood again is not */
    wake_tick(&c, 5000, 4990);
    assert(c.quiet_since != 0);
    wake_tick(&c, 5000, 0);
    assert(c.quiet_since == 0);

    /* more replies counted than packets (another CPU's, read apart):
     * no rate below 0
     */
    wake_tick(&c, 10, 20);
    assert(c.wake_rx_pps == 0 && c.wake_rx_bps == 0);

    vg_ctrl_free(&c);
    memset(&stub_metrics, 0, sizeof(stub_metrics));
}


/* The feed's entry seq, which must be of this kind. */
static const struct vg_feed_entry *
feed_kind(struct vg_ctrl *c, uint64_t seq, int kind)
{
    const struct vg_feed_entry  *ch = vg_ctrl_feed_entry(c, seq);

    assert(ch != NULL && ch->kind == kind);

    return ch;
}


/*
 * Attacks (Seawall proposal 0017 §1, §2): one starts on the tick over
 * wake_*, armed or not; ends after clear_seconds below both, its end when
 * traffic fell, before a disarm on the same tick; or with a disarm, at its
 * time. Its summary: peaks, dropped, cut (policy, aggregate), bans.
 */
static void
test_attacks(void)
{
    struct vg_config             cfg;
    struct vg_ctrl               c;
    struct vg_cidr               p, q, m;
    const struct vg_feed_entry  *ch;
    uint64_t                     t0;
    time_t                       quiet;

    vg_config_defaults(&cfg);
    cfg.remote_map_size = 16;
    cfg.wake_pps = 2000;
    cfg.wake_mbps = 1000;
    cfg.clear_seconds = 0;
    nitems = 0;
    complete_scan = 1;
    memset(&stub_metrics, 0, sizeof(stub_metrics));
    assert(vg_ctrl_init(&c, &cfg, NULL, NULL, NULL) == 0);
    c.last_m = stub_metrics;

    /* below the threshold: nothing */
    wake_tick(&c, 1000, 0);
    assert(c.state == VG_IDLE && !c.attack_open && c.seq == 0);

    /* a flood on an idle gate: it arms, and an attack starts after */
    t0 = (uint64_t) time(NULL) * 1000;
    wake_tick(&c, 5000, 0);
    assert(c.state == VG_ACTIVE && c.attack_open && c.attack.id == 1);
    feed_kind(&c, c.seq - 1, VG_FEED_ARM);
    ch = feed_kind(&c, c.seq, VG_FEED_ATTACK);
    assert(ch->attack.id == 1 && ch->attack.start_ms >= t0);
    assert(ch->attack.pps > 4900 && ch->attack.pps < 5100);

    /* peaks are the highest tick; drops while open are counted */
    stub_metrics.dropped += 100;
    wake_tick(&c, 8000, 0);
    stub_metrics.dropped += 50;
    wake_tick(&c, 6000, 0);
    assert(c.attack.pps > 7900 && c.attack.pps < 8100);

    /* cut: policy and aggregate; bans: the ban socket's; manual: neither */
    assert(vg_parse_cidr("198.18.0.1/32", &p) == 0);
    assert(vg_parse_cidr("198.18.0.2/32", &q) == 0);
    assert(vg_parse_cidr("198.18.1.0/24", &m) == 0);
    assert(vg_ctrl_drop(&c, &p, VG_REASON_POLICY) == 0);
    vg_ctrl_caller(&c, VG_SOURCE_BAN, 1000);
    assert(vg_ctrl_drop_ttl(&c, &q, 60) == 0);
    vg_ctrl_caller(&c, VG_SOURCE_SOCKET, 0);
    assert(vg_ctrl_drop(&c, &m, VG_REASON_MANUAL) == 0);
    vg_ctrl_caller(&c, VG_SOURCE_SELF, 0);
    assert(c.attack.cut == 1 && c.attack.bans == 1);

    /* a reload doesn't end it */
    vg_ctrl_reloaded(&c);
    assert(c.attack_open);

    /* quiet for clear_seconds (0 here): it ends when traffic fell; the
     * blocks keep the gate armed
     */
    quiet = time(NULL);
    wake_tick(&c, 100, 0);
    assert(!c.attack_open && c.state == VG_ACTIVE);
    ch = feed_kind(&c, c.seq, VG_FEED_ATTACK_END);
    assert(ch->attack.id == 1 && ch->attack.how == VG_ATTACK_QUIET);
    /* to the second, never before its start, which has ms */
    assert(ch->attack.end_ms >= (uint64_t) quiet * 1000
           && ch->attack.end_ms < ((uint64_t) time(NULL) + 1) * 1000
           && ch->attack.end_ms >= ch->attack.start_ms);
    assert(ch->attack.pps > 7900 && ch->attack.dropped == 150);
    assert(ch->attack.cut == 1 && ch->attack.bans == 1);
    assert(strcmp(ch->cause, "quiet") == 0);
    assert(c.have_last_attack && c.last_attack.id == 1);

    /* a flood on a gate armed by its blocks: an attack, no arm */
    wake_tick(&c, 5000, 0);
    assert(c.attack_open && c.attack.id == 2);
    feed_kind(&c, c.seq, VG_FEED_ATTACK);
    feed_kind(&c, c.seq - 1, VG_FEED_ATTACK_END);

    /* a disarm ends it, at the disarm's time, before its own entry */
    t0 = (uint64_t) time(NULL) * 1000;
    assert(vg_ctrl_disarm(&c, "command") == 0);
    assert(!c.attack_open && c.state == VG_IDLE);
    ch = feed_kind(&c, c.seq - 1, VG_FEED_ATTACK_END);
    assert(ch->attack.id == 2 && ch->attack.how == VG_ATTACK_DISARM);
    assert(ch->attack.end_ms >= t0);
    feed_kind(&c, c.seq, VG_FEED_DISARM);
    assert(c.last_attack.id == 2);

    /* no blocks: the attack's end and the automatic disarm fall on one
     * tick, the end first
     */
    wake_tick(&c, 5000, 0);
    assert(c.attack_open && c.attack.id == 3 && c.drop_count == 0);
    wake_tick(&c, 100, 0);
    assert(!c.attack_open && c.state == VG_IDLE);
    ch = feed_kind(&c, c.seq - 1, VG_FEED_ATTACK_END);
    assert(ch->attack.id == 3 && ch->attack.how == VG_ATTACK_QUIET);
    feed_kind(&c, c.seq, VG_FEED_DISARM);

    /* the host's own replies start none */
    wake_tick(&c, 5000, 4900);
    assert(c.state == VG_IDLE && !c.attack_open);

    vg_ctrl_free(&c);
    memset(&stub_metrics, 0, sizeof(stub_metrics));
}


/* Only the last VG_FEED_SIZE are kept; an older one is gone, and the epoch
 * differs from another start's.
 */
/*
 * A ban client's drop on an idle gate arms it: the arm and the block are
 * that client's, source "ban", the arm's cause "ban".
 */
static void
test_feed_ban(void)
{
    struct vg_config             cfg;
    struct vg_ctrl               c;
    struct vg_cidr               p;
    const struct vg_feed_entry  *ch;

    vg_config_defaults(&cfg);
    cfg.remote_map_size = 16;
    cfg.drop_map_size = 2;
    cfg.wake_pps = 0;
    cfg.wake_mbps = 0;
    nitems = 0;
    assert(vg_ctrl_init(&c, &cfg, NULL, NULL, NULL) == 0);

    p = v4(198, 18, 13, 1, 32);
    vg_ctrl_caller(&c, VG_SOURCE_BAN, 33);
    assert(vg_ctrl_drop_ttl(&c, &p, 60) == 0);
    vg_ctrl_caller(&c, VG_SOURCE_SELF, 0);

    ch = vg_ctrl_feed_entry(&c, 1);
    assert(ch->kind == VG_FEED_ARM && ch->source == VG_SOURCE_BAN
           && ch->uid == 33 && strcmp(ch->cause, "ban") == 0);
    ch = vg_ctrl_feed_entry(&c, 2);
    assert(ch->kind == VG_FEED_BLOCK && ch->source == VG_SOURCE_BAN
           && ch->uid == 33 && ch->reason == VG_REASON_TIMED);
    assert(strcmp(vg_source_name(VG_SOURCE_BAN), "ban") == 0
           && strcmp(vg_source_name(VG_SOURCE_SOCKET), "socket") == 0
           && strcmp(vg_source_name(VG_SOURCE_SELF), "self") == 0);

    vg_ctrl_free(&c);
}


static void
test_feed_wrap(void)
{
    struct vg_config  cfg;
    struct vg_ctrl    c, d;
    struct vg_cidr    p;
    int               i;

    vg_config_defaults(&cfg);
    cfg.remote_map_size = 16;
    nitems = 0;
    assert(vg_ctrl_init(&c, &cfg, NULL, NULL, NULL) == 0);
    assert(vg_ctrl_init(&d, &cfg, NULL, NULL, NULL) == 0);
    assert(c.epoch != d.epoch);
    c.state = VG_ACTIVE;
    p = v4(198, 18, 13, 1, 32);

    for (i = 0; i < VG_FEED_SIZE / 2 + 10; i++) {
        assert(vg_ctrl_drop(&c, &p, VG_REASON_MANUAL) == 0);
        assert(vg_ctrl_undrop(&c, &p) == 0);
    }

    assert(c.seq == VG_FEED_SIZE + 20);
    assert(vg_ctrl_feed_oldest(&c) == 21);
    assert(vg_ctrl_feed_entry(&c, 20) == NULL);
    assert(vg_ctrl_feed_entry(&c, 21)->seq == 21);
    assert(vg_ctrl_feed_entry(&c, c.seq)->kind == VG_FEED_UNBLOCK);
    assert(vg_ctrl_feed_entry(&c, c.seq + 1) == NULL);

    vg_ctrl_free(&c);
    vg_ctrl_free(&d);
}


/* Pages of blocks: by id, oldest first, from where the last page ended,
 * whether that block is still listed or not.
 */
static void
test_blocks_pages(void)
{
    struct vg_config           cfg;
    struct vg_ctrl             c;
    struct vg_cidr             p[5];
    const struct vg_drop_rec  *r;
    int                        i;

    vg_config_defaults(&cfg);
    cfg.remote_map_size = 16;
    nitems = 0;
    assert(vg_ctrl_init(&c, &cfg, NULL, NULL, NULL) == 0);
    c.state = VG_ACTIVE;
    assert(vg_ctrl_block_after(&c, 0) == NULL);

    for (i = 0; i < 5; i++) {
        p[i] = v4(198, 18, 14, i, 32);
        assert(vg_ctrl_drop(&c, &p[i], VG_REASON_MANUAL) == 0);
    }

    /* a page of two */
    r = vg_ctrl_block_after(&c, 0);
    assert(r->id == 1);
    r = vg_ctrl_block_next(&c, r);
    assert(r->id == 2);
    assert(vg_ctrl_block_next(&c, r)->id == 3);   /* hint: 2 */

    /* the next page from the hint; then the hint lifted: by walking */
    assert(vg_ctrl_block_after(&c, 2)->id == 3);
    assert(vg_ctrl_undrop(&c, &p[2]) == 0);
    assert(c.page_hint == NULL || c.page_hint->id != 3);
    assert(vg_ctrl_block_after(&c, 3)->id == 4);

    /* a lifted record handed out again gets a new id, at the end */
    assert(vg_ctrl_drop(&c, &p[2], VG_REASON_MANUAL) == 0);
    assert(nth(&c, 4)->id == 6);
    assert(vg_ctrl_block_after(&c, 5)->id == 6);
    assert(vg_ctrl_block_after(&c, 6) == NULL);

    /* a disarm forgets every record, and the hint */
    assert(vg_ctrl_disarm(&c, "test") == 0);
    assert(vg_ctrl_block_after(&c, 0) == NULL);
    assert(vg_ctrl_block_after(&c, 5) == NULL);

    vg_ctrl_free(&c);
}


int
main(void)
{
    struct vg_config cfg;
    struct vg_ctrl c;
    struct vg_cidr expired, manual;
    int i, drops_before;

    vg_config_defaults(&cfg);
    cfg.remote_map_size = 16;
    assert(vg_ctrl_init(&c, &cfg, NULL, NULL, NULL) == 0);
    assert(c.snap_cap == 32);
    c.state = VG_ACTIVE;

    assert(vg_parse_cidr("203.0.113.1/32", &expired) == 0);
    assert(vg_parse_cidr("2001:db8::bad/128", &manual) == 0);
    assert(vg_ctrl_drop(&c, &expired, VG_REASON_POLICY) == 0);
    assert(vg_ctrl_drop(&c, &manual, VG_REASON_MANUAL) == 0);
    nth(&c, 0)->inserted = 0;   /* policy drop older than ban_time */
    nitems = 0;
    complete_scan = 1;
    assert(tick(&c) == 0);
    assert(memcmp(&deleted, &expired, sizeof(expired)) == 0);
    assert(c.drop_count == 1 && nth(&c, 0)->reason == VG_REASON_MANUAL);
    assert(memcmp(&nth(&c, 0)->cidr, &manual, sizeof(manual)) == 0);

    /* Truncated walks must keep snapshots so a second look can compute a
     * rate. */
    complete_scan = 0;
    nitems = 1;
    set_v4_item(0, 10, 1000);
    drops_before = c.drop_count;
    assert(tick(&c) == 0);
    assert(vg_ctrl_snap_count(&c) == 1);
    assert(c.drop_count == drops_before);
    items[0].c.in_pkts = 1000 + cfg.threshold_pps + 1;
    assert(tick(&c) == 0);
    assert(vg_ctrl_snap_count(&c) == 1);
    assert(c.drop_count == drops_before + 1);

    /* A newly observed leftover counter is a baseline, not a flood. */
    nitems = 1;
    set_v4_item(0, 11, 1000000000);
    drops_before = c.drop_count;
    assert(tick(&c) == 0);
    assert(c.drop_count == drops_before);

    /* Truncated walk retains remotes that were not in this batch. */
    nitems = 8;

    for (i = 0; i < 8; i++) {
        set_v4_item(i, 100 + (uint32_t) i, 1);
    }

    assert(tick(&c) == 0);
    assert(vg_ctrl_snap_count(&c) == 8 + 2); /* ids 10, 11 plus 100..107 */
    nitems = 8;

    for (i = 0; i < 8; i++) {
        set_v4_item(i, 200 + (uint32_t) i, 1);
    }

    assert(tick(&c) == 0);
    assert(vg_ctrl_snap_count(&c) == 18);

    /* Complete scan prunes remotes that left the map. */
    complete_scan = 1;
    nitems = 3;
    set_v4_item(0, 200, 1);
    set_v4_item(1, 201, 1);
    set_v4_item(2, 202, 1);
    assert(tick(&c) == 0);
    assert(vg_ctrl_snap_count(&c) == 3);

    complete_scan = 1;
    nitems = 0;
    assert(tick(&c) == 0);
    assert(vg_ctrl_snap_count(&c) == 0);

    /* At cap, truncated walks keep existing entries and refuse new ones. */
    complete_scan = 0;
    nitems = 32;

    for (i = 0; i < 32; i++) {
        set_v4_item(i, 300 + (uint32_t) i, 1);
    }

    assert(tick(&c) == 0);
    assert(vg_ctrl_snap_count(&c) == 32);
    nitems = 32;

    for (i = 0; i < 32; i++) {
        set_v4_item(i, 400 + (uint32_t) i, 1);
    }

    assert(tick(&c) == 0);
    assert(vg_ctrl_snap_count(&c) == 32);

    /* A config change (reload) lifts drops that now cover local/allow,
     * manual ones included, from the list and the map; others stay. */
    {
        struct vg_cidr keep, now_local, now_allow;

        assert(vg_parse_cidr("198.18.0.0/24", &keep) == 0);
        assert(vg_parse_cidr("203.0.113.0/24", &now_local) == 0);
        assert(vg_parse_cidr("192.0.2.0/24", &now_allow) == 0);
        assert(vg_ctrl_disarm(&c, "test") == 0);
        assert(vg_ctrl_drop(&c, &keep, VG_REASON_MANUAL) == 0);
        assert(vg_ctrl_drop(&c, &now_local, VG_REASON_AGGREGATE) == 0);
        assert(vg_ctrl_drop(&c, &now_allow, VG_REASON_MANUAL) == 0);
        deleted_count = 0;
        assert(vg_ctrl_prune_protected(&c) == 0);
        assert(c.drop_count == 3 && deleted_count == 0);

        assert(vg_parse_cidr("203.0.113.5/32", &cfg.local_cidr[0]) == 0);
        cfg.local_cidr_count = 1;
        assert(vg_parse_cidr("192.0.2.99/32",
                             &cfg.allow_cidr[cfg.allow_cidr_count++]) == 0);
        assert(vg_ctrl_prune_protected(&c) == 2);
        assert(deleted_count == 2);
        assert(c.drop_count == 1);
        assert(memcmp(&nth(&c, 0)->cidr, &keep, sizeof(keep)) == 0);
    }

    vg_ctrl_free(&c);
    test_ttl();
    test_drop_index();
    test_del_fail();
    test_expire_log();
    test_drop_log();
    test_drop_log_burst();
    test_drop_log_order();
    test_pool();
    test_feed();
    test_feed_wrap();
    test_feed_ban();
    test_wake_replies();
    test_attacks();
    test_blocks_pages();
    puts("control-plane regression tests passed");

    return 0;
}
