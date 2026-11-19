
/* SPDX-License-Identifier: Apache-2.0 */

#include "ctl_server.h"
#include "ipaddr.h"
#include "log.h"
#include "maps.h"
#include "policy.h"

#include <sw/sock.h>

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>


#define VG_MAX_BLOCK_TTL  31536000     /* one year */

/* A reply's room: VG_REPLY_SIZE for most commands; a page of the feed
 * or of blocks gets more.
 */
#define VG_REPLY_SIZE       8192
#define VG_PAGE_REPLY_SIZE  65536


typedef void (*vg_ctl_handler_pt)(struct vg_ctrl *ctrl, const char *args,
    char *reply, size_t reply_size);


typedef struct {
    const char         *name;
    int                 prefix;
    int                 read;       /* also on the read-only socket */
    int                 page;       /* VG_PAGE_REPLY_SIZE */
    vg_ctl_handler_pt   handler;
} vg_ctl_command_t;


static int ctl_critical(struct vg_ctrl *ctrl, char *reply,
    size_t reply_size);
static void ctl_status(struct vg_ctrl *ctrl, const char *args,
    char *reply, size_t reply_size);
static void ctl_stats(struct vg_ctrl *ctrl, const char *args,
    char *reply, size_t reply_size);
static void ctl_arm(struct vg_ctrl *ctrl, const char *args,
    char *reply, size_t reply_size);
static void ctl_disarm(struct vg_ctrl *ctrl, const char *args,
    char *reply, size_t reply_size);
static void ctl_block(struct vg_ctrl *ctrl, const char *args,
    char *reply, size_t reply_size);
static void ctl_unblock(struct vg_ctrl *ctrl, const char *args,
    char *reply, size_t reply_size);
static int parse_ttl(const char *s, uint32_t *out);
static int vg_ctrl_reload(struct vg_ctrl *c);
static void ctl_reload(struct vg_ctrl *ctrl, const char *args,
    char *reply, size_t reply_size);
static void ctl_feed(struct vg_ctrl *ctrl, const char *args,
    char *reply, size_t reply_size);
static int feed_line(const struct vg_feed_entry *ch, char *out, size_t size);
static int status_attacks(struct vg_ctrl *ctrl, char *out, size_t size);
static void ctl_blocks(struct vg_ctrl *ctrl, const char *args,
    char *reply, size_t reply_size);
static int parse_u64(const char *s, int base, uint64_t *out);
static int ban_allowed(const vg_ctl_command_t *cmd, const char *args);


static const vg_ctl_command_t  vg_ctl_commands[] = {
    { "status",   0, 1, 0, ctl_status },
    { "stats",    0, 1, 0, ctl_stats },
    { "feed",     1, 1, 1, ctl_feed },
    { "blocks",   1, 1, 1, ctl_blocks },
    { "arm",      0, 0, 0, ctl_arm },
    { "disarm",   0, 0, 0, ctl_disarm },
    { "block ",   1, 0, 0, ctl_block },
    { "unblock ", 1, 0, 0, ctl_unblock },
    { "reload",   0, 0, 0, ctl_reload }
};


/*
 * On the ban socket, only "block <address> ttl=<seconds>": one address,
 * a /32 or /128 (or bare), and a valid ttl, nothing else. A ban client
 * bans the clients it saw; a network is an operator's decision, so a
 * compromised one can't block a whole range.
 */
static int
ban_allowed(const vg_ctl_command_t *cmd, const char *args)
{
    uint32_t         ttl;
    const char      *sp;
    struct vg_cidr   p;

    if (cmd->handler != ctl_block) {
        return 0;
    }

    sp = strchr(args, ' ');

    if (sp == NULL || parse_ttl(sp + 1, &ttl) != 0
        || vg_parse_cidr_len(args, (size_t) (sp - args), &p) != 0)
    {
        return 0;
    }

    return p.prefixlen == (p.family == AF_INET6 ? 128 : 32);
}


/*
 * Without sw_flowd's table, the first line of status: a broken
 * install (Seawall proposal 0015 §6), shown until voidgate restarts with
 * the table. No "=" in it, so a client reading key=value pairs, as
 * lua/resty/voidgate.lua does, skips it. Returns its length.
 */
static int
ctl_critical(struct vg_ctrl *ctrl, char *reply, size_t reply_size)
{
    int  n;

    if (ctrl->maps->flows_fd >= 0) {
        reply[0] = '\0';
        return 0;
    }

    n = snprintf(reply, reply_size,
                 "CRITICAL: %s: replies to the host's own flows are judged "
                 "as any other; %s\n",
                 ctrl->maps->flows_problem[0] != '\0'
                 ? ctrl->maps->flows_problem : "no sw_flowd flow table",
                 ctrl->maps->flows_fix);

    return n < 0 ? 0 : (size_t) n >= reply_size ? (int) reply_size - 1 : n;
}


static void
ctl_status(struct vg_ctrl *ctrl, const char *args, char *reply,
    size_t reply_size)
{
    int  n;

    n = ctl_critical(ctrl, reply, reply_size);

    n += snprintf(reply + n, reply_size - n,
             "state=%s armed=%d rx_pps=%.0f rx_bps=%.0f "
             "wake_rx_pps=%.0f wake_rx_bps=%.0f "
             "blocked=%d degraded=%d iface=%s hook=%s flows=%s "
             "syn_guard=%s",
             ctrl->state == VG_ACTIVE ? "active" : "idle",
             ctrl->state == VG_ACTIVE, ctrl->rx_pps, ctrl->rx_bps,
             ctrl->wake_rx_pps, ctrl->wake_rx_bps,
             ctrl->drop_count, ctrl->maps->degraded,
             ctrl->cfg->interface, vg_hook_name(ctrl->maps),
             ctrl->maps->flows_fd >= 0 ? "sw_flowd" : "none",
             ctrl->maps->syn == NULL ? "off"
             : ctrl->syn_engaged ? "engaged" : "standby");

    /* the words of Seawall proposal 0017 §2, on the same line */
    if (n > 0 && (size_t) n < reply_size) {
        (void) status_attacks(ctrl, reply + n, reply_size - (size_t) n);
    }
}


/*
 * " attack=0|1", with 1 the open attack's id, start and peaks so far; and
 * the last ended attack's record under last_attack_, once there is one.
 * Ends the line.
 */
static int
status_attacks(struct vg_ctrl *ctrl, char *out, size_t size)
{
    int                      w;
    const struct vg_attack  *a = &ctrl->attack, *l = &ctrl->last_attack;

    w = snprintf(out, size, " attack=%d", ctrl->attack_open);

    if (ctrl->attack_open && w > 0 && (size_t) w < size) {
        w += snprintf(out + w, size - (size_t) w,
                      " attack_id=%" PRIu64 " attack_since=%" PRIu64
                      " attack_tick_peak_pps=%" PRIu64
                      " attack_tick_peak_bps=%" PRIu64,
                      a->id, a->start_ms, a->pps, a->bps);
    }

    if (ctrl->have_last_attack && w > 0 && (size_t) w < size) {
        w += snprintf(out + w, size - (size_t) w,
                      " last_attack_id=%" PRIu64 " last_attack_start=%" PRIu64
                      " last_attack_end=%" PRIu64 " last_attack_how=%s"
                      " last_attack_tick_peak_pps=%" PRIu64
                      " last_attack_tick_peak_bps=%" PRIu64
                      " last_attack_dropped=%" PRIu64
                      " last_attack_cut=%u last_attack_bans=%u",
                      l->id, l->start_ms, l->end_ms,
                      vg_attack_how_name(l->how), l->pps, l->bps,
                      l->dropped, l->cut, l->bans);
    }

    if (w > 0 && (size_t) w + 1 < size) {
        out[w++] = '\n';
        out[w] = '\0';
    }

    return w;
}


/* The data path's counters, one line; the gate's state is status's. */
static void
ctl_stats(struct vg_ctrl *ctrl, const char *args, char *reply,
    size_t reply_size)
{
    struct vg_metrics  m;

    if (vg_metrics_read(ctrl->maps, &m) < 0) {
        snprintf(reply, reply_size, "error reading metrics\n");
        return;
    }

    snprintf(reply, reply_size,
             "rx_pkts=%llu rx_bytes=%llu passed=%llu dropped=%llu "
             "non_ip=%llu map_full=%llu parse_err=%llu reply_passed=%llu "
             "rx_reply_pkts=%llu rx_reply_bytes=%llu syn_unproven=%llu "
             "syn_guard_dropped=%llu syn_guard_retrans=%llu "
             "syn_guard_unready=%llu\n",
             (unsigned long long) m.rx_pkts,
             (unsigned long long) m.rx_bytes,
             (unsigned long long) m.passed,
             (unsigned long long) m.dropped,
             (unsigned long long) m.non_ip,
             (unsigned long long) m.map_full,
             (unsigned long long) m.parse_err,
             (unsigned long long) m.reply_passed,
             (unsigned long long) m.rx_reply_pkts,
             (unsigned long long) m.rx_reply_bytes,
             (unsigned long long) m.syn_unproven,
             (unsigned long long) m.syn_guard_dropped,
             (unsigned long long) m.syn_guard_retrans,
             (unsigned long long) m.syn_guard_unready);
}


static void
ctl_arm(struct vg_ctrl *ctrl, const char *args, char *reply,
    size_t reply_size)
{
    if (vg_ctrl_arm(ctrl, "command") < 0) {
        snprintf(reply, reply_size, "error: arm failed\n");

    } else {
        snprintf(reply, reply_size, "ok\n");
    }
}


static void
ctl_disarm(struct vg_ctrl *ctrl, const char *args, char *reply,
    size_t reply_size)
{
    if (vg_ctrl_disarm(ctrl, "command") < 0) {
        snprintf(reply, reply_size, "error: disarm failed\n");

    } else {
        snprintf(reply, reply_size, "ok\n");
    }
}


/* args is the line after "block " (the dispatcher strips it):
 *   "<cidr>"                manual block, stays until unblock or disarm
 *   "<cidr> ttl=<seconds>"  timed block (reason 4), lifts itself
 * The first word is always the cidr; only text after the first space in
 * args is parsed as options, so a cidr is never read as a ttl.
 */
static void
ctl_block(struct vg_ctrl *ctrl, const char *args, char *reply,
    size_t reply_size)
{
    int              rc;
    size_t           len;
    uint32_t         ttl = 0;
    const char      *sp;
    struct vg_cidr   p;

    sp = strchr(args, ' ');
    len = sp != NULL ? (size_t) (sp - args) : strlen(args);

    if (vg_parse_cidr_len(args, len, &p) < 0) {
        snprintf(reply, reply_size, "error: bad cidr\n");
        return;
    }

    if (sp != NULL && parse_ttl(sp + 1, &ttl) < 0) {
        snprintf(reply, reply_size, "error: bad ttl\n");
        return;
    }

    rc = ttl ? vg_ctrl_drop_ttl(ctrl, &p, ttl)
             : vg_ctrl_drop(ctrl, &p, VG_REASON_MANUAL);

    if (rc < 0) {
        snprintf(reply, reply_size, "error: refused or map update failed\n");

    } else {
        snprintf(reply, reply_size, "ok\n");
    }
}


static void
ctl_unblock(struct vg_ctrl *ctrl, const char *args, char *reply,
    size_t reply_size)
{
    struct vg_cidr  p;

    if (vg_parse_cidr(args, &p) < 0) {
        snprintf(reply, reply_size, "error: bad cidr\n");

    } else if (vg_ctrl_undrop(ctrl, &p) < 0) {
        snprintf(reply, reply_size, "error: map update failed\n");

    } else {
        snprintf(reply, reply_size, "ok\n");
    }
}


/* "ttl=<seconds>": only decimal digits after "ttl=" (no sign, space or
 * trailing text), 1 .. VG_MAX_BLOCK_TTL. The bound is checked per digit,
 * so the value cannot overflow.
 */
static int
parse_ttl(const char *s, uint32_t *out)
{
    uint32_t  v;

    if (strncmp(s, "ttl=", 4) != 0) {
        return -1;
    }

    for (v = 0, s += 4; *s != '\0'; s++) {
        if (*s < '0' || *s > '9' || v > VG_MAX_BLOCK_TTL) {
            return -1;
        }

        v = v * 10 + (uint32_t) (*s - '0');
    }

    /* Also rejects an empty "ttl=". */
    if (v < 1 || v > VG_MAX_BLOCK_TTL) {
        return -1;
    }

    *out = v;

    return 0;
}


static int
vg_ctrl_reload(struct vg_ctrl *c)
{
    int                    syn_guard, syn_bits;
    uint32_t               rsz, dsz;
    struct vg_config       n;
    char                   iface[VG_MAX_IFACE];
    char                   mode[16];
    char                   hook[sizeof(c->cfg->hook)];
    char                   log_file[VG_CFG_PATH_MAX];
    char                   pid_file[VG_CFG_PATH_MAX];

    if (c->cfg_path[0] == '\0') {
        return -1;
    }

    snprintf(iface, sizeof(iface), "%s", c->cfg->interface);
    snprintf(mode, sizeof(mode), "%s", c->cfg->xdp_mode);
    snprintf(hook, sizeof(hook), "%s", c->cfg->hook);
    snprintf(log_file, sizeof(log_file), "%s", c->cfg->log_file);
    snprintf(pid_file, sizeof(pid_file), "%s", c->cfg->pid_file);
    rsz = c->cfg->remote_map_size;
    dsz = c->cfg->drop_map_size;
    syn_guard = c->cfg->syn_guard;
    syn_bits = c->cfg->syn_guard_bits;

    if (vg_config_load(c->cfg_path, &n) < 0) {
        return -1;
    }

    snprintf(n.interface, sizeof(n.interface), "%s", iface);
    snprintf(n.xdp_mode, sizeof(n.xdp_mode), "%s", mode);
    snprintf(n.hook, sizeof(n.hook), "%s", hook);
    snprintf(n.log_file, sizeof(n.log_file), "%s", log_file);
    snprintf(n.pid_file, sizeof(n.pid_file), "%s", pid_file);
    n.remote_map_size = rsz;
    n.drop_map_size = dsz;

    /* the filter's thread and size are the start's */
    if (n.syn_guard != syn_guard || n.syn_guard_bits != syn_bits) {
        sw_log_warn("reload: syn_guard and syn_guard_bits take effect "
                    "at restart");
    }

    n.syn_guard = syn_guard;
    n.syn_guard_bits = syn_bits;

    if (c->iface_override[0]) {
        snprintf(n.interface, sizeof(n.interface), "%s", c->iface_override);
    }

    if (vg_config_auto_local(&n) < 0) {
        return -1;
    }

    *c->cfg = n;

    /* Before the new local map goes live: a drop covering a new local
     * address would otherwise match its inbound traffic by destination.
     */
    vg_ctrl_prune_protected(c);

    if (vg_cfg_commit(c->maps, c->state == VG_ACTIVE, c->syn_engaged,
                      c->cfg) < 0)
    {
        return -1;
    }

    if (vg_populate_allow(c->maps, c->cfg) < 0
        || vg_populate_local(c->maps, c->cfg) < 0)
    {
        return -1;
    }

    sw_log_info("reloaded %s", c->cfg_path);

    return 0;
}


static void
ctl_reload(struct vg_ctrl *ctrl, const char *args, char *reply,
    size_t reply_size)
{
    if (vg_ctrl_reload(ctrl) < 0) {
        snprintf(reply, reply_size, "error: reload failed\n");

    } else {
        vg_ctrl_reloaded(ctrl);
        snprintf(reply, reply_size, "ok\n");
    }
}


/*
 * "feed" alone: the cursor, to start from.
 * "feed <epoch> <seq>": the entries after seq, oldest first, as many as
 * fit; "more=1" if there are others after them. A cursor of another
 * epoch (voidgate restarted), older than the entries kept, or past the
 * last one is a gap: none are sent, and the reader reads the blocks back
 * and carries on from the seq in this reply.
 *
 *   epoch=<16 hex> seq=<last> oldest=<seq> gap=0|1 n=<lines> more=0|1
 *   seq=N time=<Unix ms> kind=block|unblock|arm|disarm|reload|attack|
 *       attack-end source=self|socket [uid=N] [cause=W] [id=N cidr=C
 *       reason=R expires=<Unix s, 0 if none>]
 *   attack (Seawall proposal 0017 §2): id=N wake_rx_pps=R wake_rx_bps=R,
 *       the rates that started it; attack-end: id=N start=<ms> end=<ms>
 *       how=quiet|disarm tick_peak_pps=R tick_peak_bps=R dropped=N cut=N
 *       bans=N
 */
static void
ctl_feed(struct vg_ctrl *ctrl, const char *args, char *reply,
    size_t reply_size)
{
    int                          w, gap, more;
    char                        *body, line[256], e[24];
    size_t                       used, n, len;
    uint64_t                     epoch, from, s, oldest;
    const char                  *sp;
    const struct vg_feed_entry  *ch;

    oldest = vg_ctrl_feed_oldest(ctrl);
    gap = 0;
    more = 0;
    n = 0;
    from = ctrl->seq + 1;

    if (*args == '\0') {
        goto header;
    }

    sp = *args == ' ' ? strchr(args + 1, ' ') : NULL;

    if (sp == NULL || parse_u64(sp + 1, 10, &from) < 0) {
        snprintf(reply, reply_size, "error: usage: feed <epoch> <seq>\n");
        return;
    }

    len = (size_t) (sp - (args + 1));

    if (len == 0 || len >= sizeof(e)) {
        snprintf(reply, reply_size, "error: bad epoch\n");
        return;
    }

    memcpy(e, args + 1, len);
    e[len] = '\0';

    if (parse_u64(e, 16, &epoch) < 0) {
        snprintf(reply, reply_size, "error: bad epoch\n");
        return;
    }

    if (epoch != ctrl->epoch || from > ctrl->seq || from + 1 < oldest) {
        gap = 1;
        from = ctrl->seq + 1;

    } else {
        from++;
    }

header:

    body = malloc(reply_size);

    if (body == NULL) {
        snprintf(reply, reply_size, "error: out of memory\n");
        return;
    }

    used = 0;

    /* room for the header, at most 80 bytes */
    for (s = from; s <= ctrl->seq; s++) {
        ch = vg_ctrl_feed_entry(ctrl, s);

        if (ch == NULL) {
            continue;
        }

        w = feed_line(ch, line, sizeof(line));

        if (used + (size_t) w + 80 >= reply_size) {
            more = 1;
            break;
        }

        memcpy(body + used, line, (size_t) w);
        used += (size_t) w;
        n++;
    }

    w = snprintf(reply, reply_size, "epoch=%016" PRIx64 " seq=%" PRIu64
                 " oldest=%" PRIu64 " gap=%d n=%zu more=%d\n",
                 ctrl->epoch, ctrl->seq, oldest, gap, n, more);

    memcpy(reply + w, body, used);
    reply[w + used] = '\0';
    free(body);
}


static int
feed_line(const struct vg_feed_entry *ch, char *out, size_t size)
{
    static const char  *kinds[] = {
        "block", "unblock", "arm", "disarm", "reload", "attack", "attack-end"
    };

    int   w, n;
    char  cidr[80], uid[24], cause[40];

    uid[0] = '\0';
    cause[0] = '\0';

    if (ch->source != VG_SOURCE_SELF) {
        snprintf(uid, sizeof(uid), " uid=%u", ch->uid);
    }

    if (ch->cause[0] != '\0') {
        snprintf(cause, sizeof(cause), " cause=%s", ch->cause);
    }

    w = snprintf(out, size, "seq=%" PRIu64 " time=%" PRIu64 " kind=%s "
                 "source=%s%s%s", ch->seq, ch->time_ms,
                 ch->kind < sizeof(kinds) / sizeof(kinds[0])
                 ? kinds[ch->kind] : "unknown",
                 vg_source_name(ch->source), uid, cause);

    if (ch->kind == VG_FEED_BLOCK || ch->kind == VG_FEED_UNBLOCK) {
        vg_cidr_to_str(&ch->cidr, cidr, sizeof(cidr));
        n = snprintf(out + w, size - (size_t) w,
                     " id=%" PRIu64 " cidr=%s reason=%s expires=%lld",
                     ch->id, cidr, vg_reason_name(ch->reason),
                     (long long) ch->expires);
        w += n;

    } else if (ch->kind == VG_FEED_ATTACK) {
        n = snprintf(out + w, size - (size_t) w,
                     " id=%" PRIu64 " wake_rx_pps=%" PRIu64
                     " wake_rx_bps=%" PRIu64,
                     ch->attack.id, ch->attack.pps, ch->attack.bps);
        w += n;

    } else if (ch->kind == VG_FEED_ATTACK_END) {
        n = snprintf(out + w, size - (size_t) w,
                     " id=%" PRIu64 " start=%" PRIu64 " end=%" PRIu64
                     " how=%s tick_peak_pps=%" PRIu64 " tick_peak_bps=%"
                     PRIu64 " dropped=%" PRIu64 " cut=%u bans=%u",
                     ch->attack.id, ch->attack.start_ms, ch->attack.end_ms,
                     vg_attack_how_name(ch->attack.how), ch->attack.pps,
                     ch->attack.bps, ch->attack.dropped, ch->attack.cut,
                     ch->attack.bans);
        w += n;
    }

    out[w++] = '\n';
    out[w] = '\0';

    return w;
}


/*
 * Every listed block, in pages: "blocks" for the first, "blocks after
 * <id>" for the one after id, until "next=end". Oldest first; ids only
 * grow, so a block added while the pages are read comes in a later one.
 * seq is the last change at this page: after a gap, the reader carries on
 * from the seq of the first page, and a change since then may name a
 * block it has already read.
 *
 *   epoch=<16 hex> seq=N n=<lines> next=<id>|end
 *   id=N cidr=C reason=R inserted=<Unix s> expires=<Unix s, 0 if none>
 */
static void
ctl_blocks(struct vg_ctrl *ctrl, const char *args, char *reply,
    size_t reply_size)
{
    int                        w, n;
    char                      *body, line[192], cidr[80], next[24];
    size_t                     used;
    uint64_t                   after;
    const struct vg_drop_rec  *r, *last;

    after = 0;

    if (*args != '\0'
        && (strncmp(args, " after ", 7) != 0
            || parse_u64(args + 7, 10, &after) < 0))
    {
        snprintf(reply, reply_size, "error: usage: blocks [after <id>]\n");
        return;
    }

    body = malloc(reply_size);

    if (body == NULL) {
        snprintf(reply, reply_size, "error: out of memory\n");
        return;
    }

    used = 0;
    n = 0;
    last = NULL;

    for (r = vg_ctrl_block_after(ctrl, after);
         r != NULL && n < VG_BLOCKS_PAGE;
         r = vg_ctrl_block_next(ctrl, r))
    {
        vg_cidr_to_str(&r->cidr, cidr, sizeof(cidr));
        w = snprintf(line, sizeof(line), "id=%" PRIu64 " cidr=%s reason=%s "
                     "inserted=%lld expires=%lld\n", r->id, cidr,
                     vg_reason_name(r->reason), (long long) r->inserted,
                     r->reason == VG_REASON_TIMED
                     ? (long long) r->expires : 0LL);

        if (used + (size_t) w + 80 >= reply_size) {
            break;
        }

        memcpy(body + used, line, (size_t) w);
        used += (size_t) w;
        last = r;
        n++;
    }

    if (r == NULL || last == NULL) {
        snprintf(next, sizeof(next), "end");

    } else {
        snprintf(next, sizeof(next), "%" PRIu64, last->id);
    }

    w = snprintf(reply, reply_size, "epoch=%016" PRIx64 " seq=%" PRIu64
                 " n=%d next=%s\n", ctrl->epoch, ctrl->seq, n, next);

    memcpy(reply + w, body, used);
    reply[w + used] = '\0';
    free(body);
}


/* Digits only, in base 10 or 16, at most 64 bits. */
static int
parse_u64(const char *s, int base, uint64_t *out)
{
    int       d;
    uint64_t  v;

    if (*s == '\0') {
        return -1;
    }

    for (v = 0; *s != '\0'; s++) {
        if (*s >= '0' && *s <= '9') {
            d = *s - '0';

        } else if (base == 16 && *s >= 'a' && *s <= 'f') {
            d = *s - 'a' + 10;

        } else if (base == 16 && *s >= 'A' && *s <= 'F') {
            d = *s - 'A' + 10;

        } else {
            return -1;
        }

        if (v > (UINT64_MAX - (uint64_t) d) / (uint64_t) base) {
            return -1;
        }

        v = v * (uint64_t) base + (uint64_t) d;
    }

    *out = v;

    return 0;
}


/* group (-g): NULL leaves the socket to root alone; otherwise members of
 * that group (sw_configd, an nginx/OpenResty worker user) get the full
 * control protocol. One that /etc/group doesn't know is an error. The
 * read-only socket (-R) is made the same way, for its group.
 */
int
vg_ctl_server_listen(const char *path, const char *group, char *err,
    size_t errlen)
{
    return sw_sock_listen_unix(path, 0660, group, err, errlen);
}


void
vg_ctl_server_handle(struct vg_ctrl *ctrl, int cfd, int mode)
{
    char                    *nl;
    uid_t                    uid;
    size_t                   i, len, used = 0;
    ssize_t                  n;
    const vg_ctl_command_t  *cmd;
    char                     req[256];
    static char              reply[VG_PAGE_REPLY_SIZE];

    for (;;) {
        n = read(cfd, req + used, sizeof(req) - 1 - used);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }

            return;
        }

        if (n == 0) {
            if (used == 0) {
                return;
            }

            break;
        }

        nl = memchr(req + used, '\n', (size_t) n);
        len = nl != NULL ? (size_t) (nl - (req + used)) : (size_t) n;

        if (memchr(req + used, 0, len) != NULL) {
            snprintf(reply, sizeof(reply), "error: bad command\n");
            goto send_reply;
        }

        used += len;

        if (nl != NULL) {
            break;
        }

        if (used == sizeof(req) - 1) {
            snprintf(reply, sizeof(reply), "error: command too long\n");
            goto send_reply;
        }
    }

    req[used] = 0;

    snprintf(reply, sizeof(reply), "error: unknown command\n");

    for (i = 0; i < sizeof(vg_ctl_commands) / sizeof(vg_ctl_commands[0]); i++) {
        cmd = &vg_ctl_commands[i];
        len = strlen(cmd->name);

        if (!(cmd->prefix ? strncmp(req, cmd->name, len) == 0
                          : strcmp(req, cmd->name) == 0))
        {
            continue;
        }

        /* "feed" and "blocks" take arguments after a space, or none */
        if (cmd->prefix && cmd->name[len - 1] != ' '
            && req[len] != '\0' && req[len] != ' ')
        {
            continue;
        }

        if (mode == VG_CTL_READ && !cmd->read) {
            snprintf(reply, sizeof(reply), "error: read-only socket\n");
            break;
        }

        /* the ban socket: one address's block that expires, nothing else */
        if (mode == VG_CTL_BAN && !ban_allowed(cmd, req + len)) {
            snprintf(reply, sizeof(reply),
                     "error: denied: the ban socket takes only "
                     "block <address> ttl=<seconds>\n");
            break;
        }

        /* the changes a command causes are its caller's */
        uid = (uid_t) -1;

        if (mode != VG_CTL_READ) {
            (void) sw_sock_peer(cfd, NULL, &uid, NULL);
            vg_ctrl_caller(ctrl, mode == VG_CTL_BAN ? VG_SOURCE_BAN
                                                    : VG_SOURCE_SOCKET,
                           (uint32_t) uid);
        }

        reply[0] = 0;
        cmd->handler(ctrl, cmd->prefix ? req + len : NULL, reply,
                     cmd->page ? sizeof(reply) : VG_REPLY_SIZE);
        vg_ctrl_caller(ctrl, VG_SOURCE_SELF, 0);
        break;
    }

send_reply:

    (void) sw_sock_send_all(cfd, reply, strlen(reply));
}
