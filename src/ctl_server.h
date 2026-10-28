
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef _VG_CTL_SERVER_H_INCLUDED_
#define _VG_CTL_SERVER_H_INCLUDED_

#include <stddef.h>


struct vg_ctrl;


int vg_ctl_server_listen(const char *path, const char *group, char *err,
    size_t errlen);
/* The caller sets socket timeouts and closes fd after handling. */
void vg_ctl_server_handle(struct vg_ctrl *ctrl, int fd);

#endif /* _VG_CTL_SERVER_H_INCLUDED_ */
