
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef _VG_CONFIG_H_INCLUDED_
#define _VG_CONFIG_H_INCLUDED_

#include "bpf/voidgate.h"
#include "ipaddr.h"

#include <stdint.h>

#define VG_MAX_CIDR_LIST  256
#define VG_MAX_IFACE  32
#define VG_CFG_PATH_MAX  256

struct vg_config {
    char              interface[VG_MAX_IFACE];
    char              xdp_mode[16]; /* auto, native, skb */
    char              hook[8];      /* auto, xdp, tc */
    char              log_file[VG_CFG_PATH_MAX];
    char              pid_file[VG_CFG_PATH_MAX];
    uint64_t          wake_pps;
    uint64_t          wake_mbps;
    int               idle_poll_ms;
    int               clear_seconds;
    uint64_t          threshold_pps;
    uint64_t          threshold_mbps;
    int               ban_time;
    int               aggregate_k;
    int               metrics_port;
    uint32_t          remote_map_size;
    uint32_t          drop_map_size;
    int               reply_idle_seconds;
    uint16_t          allow_ports[VG_MAX_ALLOW_PORTS];
    int               allow_port_count;
    struct vg_cidr    local_cidr[VG_MAX_CIDR_LIST];
    int               local_cidr_count;
    struct vg_cidr    allow_cidr[VG_MAX_CIDR_LIST];
    int               allow_cidr_count;
    int               auto_local;
};


void vg_config_defaults(struct vg_config *c);
int vg_config_load(const char *path, struct vg_config *c);
int vg_config_auto_local(struct vg_config *c);
int vg_cidr_is_protected(const struct vg_config *cfg,
    const struct vg_cidr *p);

#endif /* _VG_CONFIG_H_INCLUDED_ */
