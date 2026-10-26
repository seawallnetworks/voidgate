
/* SPDX-License-Identifier: Apache-2.0 */

#include "ctl_server.h"
#include "ipaddr.h"
#include "log.h"
#include "maps.h"
#include "policy.h"

#include <errno.h>
#include <grp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>


#define VG_MAX_DROP_TTL  31536000     /* one year */


typedef void (*vg_ctl_handler_pt)(struct vg_ctrl *ctrl, const char *args,
    char *reply, size_t reply_size);


typedef struct {
    const char         *name;
    int                 prefix;
    vg_ctl_handler_pt   handler;
} vg_ctl_command_t;


static void ctl_status(struct vg_ctrl *ctrl, const char *args,
    char *reply, size_t reply_size);
static void ctl_stats(struct vg_ctrl *ctrl, const char *args,
    char *reply, size_t reply_size);
static void ctl_drops(struct vg_ctrl *ctrl, const char *args,
    char *reply, size_t reply_size);
static void ctl_arm(struct vg_ctrl *ctrl, const char *args,
    char *reply, size_t reply_size);
static void ctl_disarm(struct vg_ctrl *ctrl, const char *args,
    char *reply, size_t reply_size);
static void ctl_drop(struct vg_ctrl *ctrl, const char *args,
    char *reply, size_t reply_size);
static void ctl_undrop(struct vg_ctrl *ctrl, const char *args,
    char *reply, size_t reply_size);
static int parse_ttl(const char *s, uint32_t *out);
static int vg_ctrl_reload(struct vg_ctrl *c);
static void ctl_reload(struct vg_ctrl *ctrl, const char *args,
    char *reply, size_t reply_size);


static const vg_ctl_command_t  vg_ctl_commands[] = {
    { "status",  0, ctl_status },
    { "stats",   0, ctl_stats },
    { "drops",   0, ctl_drops },
    { "arm",     0, ctl_arm },
    { "disarm",  0, ctl_disarm },
    { "drop ",   1, ctl_drop },
    { "undrop ", 1, ctl_undrop },
    { "reload",  0, ctl_reload }
};


static void
ctl_status(struct vg_ctrl *ctrl, const char *args, char *reply,
    size_t reply_size)
{
    snprintf(reply, reply_size,
             "state=%s armed=%d rx_pps=%.0f rx_bps=%.0f "
             "prefixes=%d iface=%s hook=%s degraded=%d\n",
             ctrl->state == VG_ACTIVE ? "active" : "idle",
             ctrl->state == VG_ACTIVE, ctrl->rx_pps, ctrl->rx_bps,
             ctrl->drop_count,
             ctrl->cfg->interface, vg_hook_name(ctrl->maps),
             ctrl->maps->degraded);
}


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
             "non_ip=%llu map_full=%llu parse_err=%llu reply_passed=%llu\n"
             "rx_pps=%.0f rx_bps=%.0f state=%s prefixes=%d flows=%s\n",
             (unsigned long long) m.rx_pkts,
             (unsigned long long) m.rx_bytes,
             (unsigned long long) m.passed,
             (unsigned long long) m.dropped,
             (unsigned long long) m.non_ip,
             (unsigned long long) m.map_full,
             (unsigned long long) m.parse_err,
             (unsigned long long) m.reply_passed,
             ctrl->rx_pps,
             ctrl->rx_bps,
             ctrl->state == VG_ACTIVE ? "active" : "idle",
             ctrl->drop_count,
             ctrl->maps->flows_fd >= 0 ? "sw_flowd" : "none");
}


static void
ctl_drops(struct vg_ctrl *ctrl, const char *args, char *reply,
    size_t reply_size)
{
    size_t                     used = 0;
    struct vg_list            *l;
    const struct vg_drop_rec  *r;

    if (ctrl->drop_count == 0) {
        snprintf(reply, reply_size, "(none)\n");
        return;
    }

    reply[0] = 0;

    /* Oldest first. */
    for (l = ctrl->drop_all.next;
         l != &ctrl->drop_all && used + 80 < reply_size;
         l = l->next)
    {
        int   n;
        char  p[80];

        r = vg_list_entry(l, struct vg_drop_rec, all);
        vg_cidr_to_str(&r->cidr, p, sizeof(p));
        n = snprintf(reply + used, reply_size - used,
                     "%s reason=%u age=%ld\n", p, r->reason,
                     (long) (time(NULL) - r->inserted));

        if (n > 0) {
            used += (size_t) n;
        }
    }
}


static void
ctl_arm(struct vg_ctrl *ctrl, const char *args, char *reply,
    size_t reply_size)
{
    if (vg_ctrl_arm(ctrl, "ctl") < 0) {
        snprintf(reply, reply_size, "error: arm failed\n");

    } else {
        snprintf(reply, reply_size, "ok\n");
    }
}


static void
ctl_disarm(struct vg_ctrl *ctrl, const char *args, char *reply,
    size_t reply_size)
{
    if (vg_ctrl_disarm(ctrl, "ctl") < 0) {
        snprintf(reply, reply_size, "error: disarm failed\n");

    } else {
        snprintf(reply, reply_size, "ok\n");
    }
}


/* args is the line after "drop " (the dispatcher strips it):
 *   "<cidr>"                manual drop, stays until undrop or disarm
 *   "<cidr> ttl=<seconds>"  timed drop (reason 4), lifts itself
 * The first word is always the cidr; only text after the first space in
 * args is parsed as options, so a cidr is never read as a ttl.
 */
static void
ctl_drop(struct vg_ctrl *ctrl, const char *args, char *reply,
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
ctl_undrop(struct vg_ctrl *ctrl, const char *args, char *reply,
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
 * trailing text), 1 .. VG_MAX_DROP_TTL. The bound is checked per digit,
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
        if (*s < '0' || *s > '9' || v > VG_MAX_DROP_TTL) {
            return -1;
        }

        v = v * 10 + (uint32_t) (*s - '0');
    }

    /* Also rejects an empty "ttl=". */
    if (v < 1 || v > VG_MAX_DROP_TTL) {
        return -1;
    }

    *out = v;

    return 0;
}


static int
vg_ctrl_reload(struct vg_ctrl *c)
{
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

    if (vg_cfg_commit(c->maps, c->state == VG_ACTIVE, c->cfg) < 0) {
        return -1;
    }

    if (vg_populate_allow(c->maps, c->cfg) < 0
        || vg_populate_local(c->maps, c->cfg) < 0)
    {
        return -1;
    }

    vg_log("reloaded %s", c->cfg_path);

    return 0;
}


static void
ctl_reload(struct vg_ctrl *ctrl, const char *args, char *reply,
    size_t reply_size)
{
    if (vg_ctrl_reload(ctrl) < 0) {
        snprintf(reply, reply_size, "error: reload failed\n");

    } else {
        snprintf(reply, reply_size, "ok\n");
    }
}


int
vg_ctl_server_alive(const char *path)
{
    struct sockaddr_un addr;
    int fd, alive;

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

    if (fd < 0) {
        return 0;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

    /* A leftover socket file from a crash refuses; a daemon accepts. */
    alive = connect(fd, (struct sockaddr *) &addr, sizeof(addr)) == 0;
    close(fd);

    return alive;
}


/* group (-g): "" leaves the socket root-only; otherwise members of that
 * group (sw_configd, an nginx/OpenResty worker user) get the full control
 * protocol.
 */
int
vg_ctl_server_listen(const char *path, const char *group)
{
    struct group *gr;
    struct sockaddr_un addr;
    int fd;

    unlink(path);
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

    if (fd < 0) {
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    chmod(path, 0660);

    if (group[0] != '\0') {
        gr = getgrnam(group);

        if (gr == NULL) {
            vg_warn("-g %s: no such group", group);

        } else if (chown(path, (uid_t) -1, gr->gr_gid) < 0) {
            vg_warn("-g %s: chown %s: %s", group, path,
                    strerror(errno));
        }
    }

    if (listen(fd, 16) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}


void
vg_ctl_server_handle(struct vg_ctrl *ctrl, int cfd)
{
    char                    *nl;
    size_t                   i, len, used = 0;
    ssize_t                  n;
    const vg_ctl_command_t  *cmd;
    char                     req[256], reply[8192];

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

        if (cmd->prefix ? strncmp(req, cmd->name, len) == 0
                        : strcmp(req, cmd->name) == 0)
        {
            reply[0] = 0;
            cmd->handler(ctrl, cmd->prefix ? req + len : NULL,
                         reply, sizeof(reply));
            break;
        }
    }

send_reply:

    len = strlen(reply);
    used = 0;

    while (used < len) {
        n = send(cfd, reply + used, len - used, MSG_NOSIGNAL);

        if (n < 0 && errno == EINTR) {
            continue;
        }

        if (n <= 0) {
            return;
        }

        used += (size_t) n;
    }
}
