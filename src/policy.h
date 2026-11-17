
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

/* Changes kept for "changes since" (Seawall proposal 0012 §2): a reader
 * whose cursor is older than these has a gap, and reads the blocks back.
 */
#define VG_CHANGES  8192

/* A blocks page holds at most this many. */
#define VG_BLOCKS_PAGE  256

enum vg_change_kind {
    VG_CHANGE_BLOCK = 0,    /* a new block, or one re-dropped with a new
                               reason or expiry */
    VG_CHANGE_UNBLOCK,      /* one block lifted */
    VG_CHANGE_ARM,
    VG_CHANGE_DISARM,       /* every block lifted with it */
    VG_CHANGE_RELOAD
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
struct vg_change {
    uint64_t                seq;        /* 1, 2, ... since start; 0 unused */
    uint64_t                time_ms;    /* Unix time */
    uint64_t                id;         /* the block's, for block, unblock */
    time_t                  expires;    /* a timed block's lift time */
    struct vg_cidr          cidr;
    uint32_t                reason;
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
    double                  rx_pps;
    double                  rx_bps;
    time_t                  quiet_since;
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
    struct vg_change       *changes;        /* VG_CHANGES, by seq */
    int                     caller_source;  /* enum vg_source: whose
                                               command runs */
    uint32_t                caller_uid;
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

/* Record a reload that went through (the caller's, if a command's). */
void vg_ctrl_reloaded(struct vg_ctrl *c);

/* The change with this seq, or NULL: not made yet, or no longer kept. */
const struct vg_change *vg_ctrl_change(const struct vg_ctrl *c,
    uint64_t seq);

/* The oldest seq still kept; seq + 1 when there are none. */
uint64_t vg_ctrl_changes_oldest(const struct vg_ctrl *c);

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
