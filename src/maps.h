
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef _VG_MAPS_H_INCLUDED_
#define _VG_MAPS_H_INCLUDED_

#include "bpf/voidgate.h"
#include "config.h"
#include "ipaddr.h"

#include <stddef.h>
#include <stdint.h>

struct voidgate_bpf;
struct xdp_program;

enum vg_hook {
    VG_HOOK_NONE = 0,
    VG_HOOK_XDP,            /* in libxdp's dispatcher */
    VG_HOOK_TC              /* TC ingress */
};

struct vg_maps {
    struct voidgate_bpf  *skel;
    int                   ncpus;
    int                   ifindex;
    enum vg_hook          hook;
    int                   degraded;     /* TC: another program holds XDP */
    int                   xdp_mode;     /* enum xdp_attach_mode */
    struct xdp_program   *xdp_prog;
    int                   tcx_fd;       /* -1: classic TC */
    void                 *sum_scratch;
    size_t                sum_scratch_size;
    int                   flows_fd;     /* sw_flowd's table; -1: none */
    int                   flows_config_fd;
    uint32_t              flows_size;
    int                   flows_stats_fd;
};


int vg_maps_open(struct vg_maps *m, struct vg_config *cfg);
void vg_maps_close(struct vg_maps *m);
int vg_attach(struct vg_maps *m, const struct vg_config *cfg);
void vg_detach(struct vg_maps *m);
const char *vg_hook_name(const struct vg_maps *m);

int vg_cfg_commit(struct vg_maps *m, uint32_t armed,
    const struct vg_config *cfg);

int vg_metrics_read(struct vg_maps *m, struct vg_metrics *out);
int vg_sum_percpu(struct vg_maps *m, int map_fd, const void *key,
    size_t val_size, void *out_sum);

typedef void (*vg_remote_pt)(int family, const uint8_t *addr,
    const struct host_counters *sum, void *ctx);

/* Walk remote_v4 then remote_v6, at most `budget` keys each.
 * Returns 1 if both maps reached EOF, 0 if either walk was truncated,
 * -1 on error.
 */
int vg_remote_foreach(struct vg_maps *m, uint32_t budget, vg_remote_pt fn,
    void *ctx);

int vg_drop_add(struct vg_maps *m, const struct vg_cidr *p, uint32_t reason,
    uint32_t now);
int vg_drop_del(struct vg_maps *m, const struct vg_cidr *p);
int vg_drop_flush(struct vg_maps *m);

int vg_flows_stats(struct vg_maps *m, uint64_t *entries, uint64_t *evicted);

int vg_populate_local(struct vg_maps *m, const struct vg_config *cfg);
int vg_populate_allow(struct vg_maps *m, const struct vg_config *cfg);

int vg_maps_metrics_fd(struct vg_maps *m);
int vg_maps_remote_v4_fd(struct vg_maps *m);
int vg_maps_remote_v6_fd(struct vg_maps *m);

#endif /* _VG_MAPS_H_INCLUDED_ */
