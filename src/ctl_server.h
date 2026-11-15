
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef _VG_CTL_SERVER_H_INCLUDED_
#define _VG_CTL_SERVER_H_INCLUDED_

#include <stddef.h>


struct vg_ctrl;


int vg_ctl_server_listen(const char *path, const char *group, char *err,
    size_t errlen);
/* Which socket a connection came on, and so what it may do. */
enum vg_ctl_mode {
    VG_CTL_FULL = 0,    /* the control socket: every command */
    VG_CTL_READ,        /* the read-only socket: status, stats, drops,
                           changes and blocks */
    VG_CTL_BAN          /* the ban socket: drop <cidr> ttl=N only, its
                           changes from source "ban" */
};

/* The caller sets socket timeouts and closes fd after handling. */
void vg_ctl_server_handle(struct vg_ctrl *ctrl, int fd, int mode);

#endif /* _VG_CTL_SERVER_H_INCLUDED_ */
