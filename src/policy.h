
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef _VG_POLICY_H_INCLUDED_
#define _VG_POLICY_H_INCLUDED_

#include "config.h"
#include "list.h"
#include "maps.h"

#include <stddef.h>
#include <time.h>

enum vg_state { VG_IDLE = 0, VG_ACTIVE = 1 };

#define VG_SNAP_BUCKETS  4096

/* Prefixes a tick's "blocked" and "expired" lines name; past this many
 * the line gives counts by reason after the first ones.
 */
#define VG_LOG_CIDRS  8

/* Entries kept in the feed (Seawall proposal 0012 §2): a reader
 * whose cursor is older than these has a gap, and reads the blocks back.
 */
#define VG_FEED_SIZE  8192

/* A blocks page holds at most this many. */
#define VG_BLOCKS_PAGE  256

enum vg_feed_kind {
    VG_FEED_BLOCK = 0,      /* a new block, or one re-dropped with a new
                               reason or expiry */
    VG_FEED_UNBLOCK,        /* one block lifted */
    VG_FEED_ARM,
    VG_FEED_DISARM,         /* every block lifted with it */
    VG_FEED_RELOAD,
    VG_FEED_ATTACK,         /* an attack started (Seawall proposal 0017) */
    VG_FEED_ATTACK_END,     /* and ended, with its summary */
    VG_FEED_SYN_ENGAGE,     /* first-SYN drop engaged (Seawall proposal
                               0023 §6), in the open attack if any */
    VG_FEED_SYN_STANDBY     /* and back to standby */
};

/* An estimated false-pass rate over this asks for more syn_guard_bits. */
#define VG_SYN_FP_WARN  0.01
/* syn_guard_unready rising is shown in status this long after. */
#define VG_SYN_UNREADY_SHOW  60

/* How an attack ended (Seawall proposal 0017 §1). */
enum vg_attack_how {
    VG_ATTACK_QUIET = 0,    /* rx, less replies, below both wake_* for
                               clear_seconds; end is when it fell */
    VG_ATTACK_DISARM        /* the gate disarmed with it open: a command,
                               or shutdown; end is the disarm's time */
};

/*
 * One attack: from the first tick over wake_*, armed or not, to
 * clear_seconds below both, or a disarm. Rates are rx less the replies to
 * the host's own flows, as wake_* see them (wake_rx_*).
 */
struct vg_attack {
    uint64_t                id;         /* 1, 2, ... since start */
    uint64_t                start_ms;   /* Unix time */
    uint64_t                end_ms;     /* 0 while open */
    uint64_t                pps;        /* the start's tick, in an attack
                                           entry; the highest tick so far,
                                           or of it, otherwise */
    uint64_t                bps;
    uint64_t                dropped;    /* all the drop list dropped while
                                           open */
    uint64_t                syn_dropped;  /* first SYNs dropped while open
                                             (Seawall proposal 0023) */
    uint32_t                cut;        /* policy and aggregate blocks
                                           added while open */
    uint32_t                bans;       /* ban socket blocks added */
    uint8_t                 how;        /* enum vg_attack_how, ended */
};

/* Where a change came from: voidgate itself, a command on the control
 * socket, or a drop on the ban socket (Seawall proposal 0012 §2).
 */
enum vg_source {
    VG_SOURCE_SELF = 0,
    VG_SOURCE_SOCKET,
    VG_SOURCE_BAN
};

/* One change. A change made by a command on the control or ban socket is
 * that caller's (its source and uid); voidgate's own are "self".
 */
struct vg_feed_entry {
    uint64_t                seq;        /* 1, 2, ... since start; 0 unused */
    uint64_t                time_ms;    /* Unix time */
    union {
        struct {                        /* block, unblock */
            uint64_t        id;
            time_t          expires;    /* a timed block's lift time */
            struct vg_cidr  cidr;
            uint32_t        reason;
        };
        struct vg_attack    attack;     /* attack, attack-end */
    };
    uint32_t                uid;
    uint8_t                 kind;
    uint8_t                 source;     /* enum vg_source */
    char                    cause[22];  /* "wake-threshold", "expired"... */
};

struct vg_logged_drop {
    struct vg_cidr          cidr;
    uint32_t                reason;
};

/* One listed drop. Records live in drop_pool and never move, so the list
 * nodes below stay valid while linked.
 */
struct vg_drop_rec {
    struct vg_cidr          cidr;
    uint32_t                reason;
    time_t                  inserted;
    time_t                  expires;    /* VG_REASON_TIMED only */
    uint64_t                id;         /* 1, 2, ... while listed; else 0 */
    struct vg_hlist_node    hash;       /* drop_heads bucket chain */
    struct vg_list          all;        /* drop_all, or drop_free if unused */
};


struct vg_snap_ent;

struct vg_ctrl {
    enum vg_state           state;
    struct vg_config       *cfg;
    struct vg_maps         *maps;
    char                    cfg_path[VG_CFG_PATH_MAX];
    char                    iface_override[VG_MAX_IFACE];
    struct vg_metrics       last_m;
    int                     have_last_m;
    struct timespec         last_tick;
    int                     have_last_tick;
    double                  rx_pps;         /* all received, last tick */
    double                  rx_bps;
    double                  wake_rx_pps;    /* less replies to the host's
                                               own flows: what wake_* and
                                               the quiet time compare */
    double                  wake_rx_bps;
    time_t                  quiet_since;
    /* first-SYN drop (Seawall proposal 0023 §1): engaged while SYNs
     * from unproven addresses alone are over wake_pps, until
     * clear_seconds below it, or the disarm
     */
    int                     syn_engaged;
    double                  syn_pps;        /* syn_unproven, last tick */
    double                  syn_drop_pps;   /* first SYNs dropped */
    time_t                  syn_quiet_since;
    double                  syn_fp_est;     /* spoofed SYNs passing as
                                               retransmissions, 0 to 1,
                                               estimated while engaged */
    int                     syn_fp_warned;  /* this engaged spell */
    uint64_t                syn_unready;    /* passed unfiltered, last tick
                                               they did */
    time_t                  syn_unready_at;
    struct vg_drop_rec     *drop_pool;      /* 2 x drop_map_size (v4 + v6) */
    unsigned                drop_pool_cap;
    unsigned                drop_used;      /* pool records ever handed out */
    struct vg_list          drop_free;      /* lifted records, for reuse */
    struct vg_list          drop_all;       /* listed drops, oldest first */
    int                     drop_count;
    struct vg_hlist_head   *drop_heads;
    unsigned                drop_nbuckets;  /* power of two */
    int                     drops_new[VG_REASON_TIMED + 1]; /* this tick */
    int                     drops_again;    /* re-drops this tick */
    struct vg_logged_drop   drops_shown[VG_LOG_CIDRS]; /* first new ones */
    int                     drops_shown_n;
    struct vg_snap_ent     *snap_pool;
    struct vg_snap_ent     *snap_free;
    struct vg_snap_ent     *snaps[VG_SNAP_BUCKETS];
    unsigned                snap_cap;
    uint32_t                snap_gen;
    int                     refused_full;   /* drop list full, this tick */
    uint64_t                drop_ids;       /* the last id handed out */
    struct vg_drop_rec     *page_hint;      /* where the last page ended */
    uint64_t                epoch;          /* drawn at start, never 0 */
    uint64_t                seq;            /* the last change's */
    struct vg_feed_entry   *feed;           /* VG_FEED_SIZE, by seq */
    int                     caller_source;  /* enum vg_source: whose
                                               command runs */
    uint32_t                caller_uid;
    int                     attack_open;
    struct vg_attack        attack;         /* the open one, peaks so far */
    uint64_t                attack_dropped; /* metrics' dropped at its start */
    uint64_t                attack_syn_dropped;
    uint64_t                attack_ids;     /* the last id handed out */
    int                     have_last_attack;
    struct vg_attack        last_attack;    /* the last ended; a restart
                                               forgets it */
};


int vg_ctrl_init(struct vg_ctrl *c, struct vg_config *cfg,
    struct vg_maps *maps, const char *cfg_path,
    const char *iface_ov);
void vg_ctrl_free(struct vg_ctrl *c);
int vg_ctrl_arm(struct vg_ctrl *c, const char *why);
int vg_ctrl_disarm(struct vg_ctrl *c, const char *why);
int vg_ctrl_tick(struct vg_ctrl *c);
int vg_ctrl_drop(struct vg_ctrl *c, const struct vg_cidr *p, uint32_t reason);
int vg_ctrl_drop_ttl(struct vg_ctrl *c, const struct vg_cidr *p,
    uint32_t ttl);
int vg_ctrl_undrop(struct vg_ctrl *c, const struct vg_cidr *p);
int vg_ctrl_prune_protected(struct vg_ctrl *c);

/*
 * A socket's caller while its command runs: the changes it causes are its
 * own. vg_ctrl_caller(c, VG_SOURCE_SELF, 0) after, back to "self".
 */
void vg_ctrl_caller(struct vg_ctrl *c, int source, uint32_t uid);

/* "self", "socket" or "ban" */
const char *vg_source_name(int source);

/* "quiet" or "disarm" */
const char *vg_attack_how_name(int how);

/* Record a reload that went through (the caller's, if a command's). */
void vg_ctrl_reloaded(struct vg_ctrl *c);

/* The change with this seq, or NULL: not made yet, or no longer kept. */
const struct vg_feed_entry *vg_ctrl_feed_entry(const struct vg_ctrl *c,
    uint64_t seq);

/* The oldest seq still kept; seq + 1 when there are none. */
uint64_t vg_ctrl_feed_oldest(const struct vg_ctrl *c);

/* The first listed block whose id is past after, or NULL; then the next
 * one with vg_ctrl_block_next(). Ids grow along the list, oldest first.
 */
const struct vg_drop_rec *vg_ctrl_block_after(struct vg_ctrl *c,
    uint64_t after);
const struct vg_drop_rec *vg_ctrl_block_next(struct vg_ctrl *c,
    const struct vg_drop_rec *r);

const char *vg_reason_name(uint32_t reason);

#if (VG_CTRL_TEST)
unsigned vg_ctrl_snap_count(const struct vg_ctrl *c);
struct vg_drop_rec *vg_ctrl_drops_find(struct vg_ctrl *c,
    const struct vg_cidr *p);
int vg_ctrl_drops_check(struct vg_ctrl *c);
#endif /* VG_CTRL_TEST */

#endif /* _VG_POLICY_H_INCLUDED_ */
