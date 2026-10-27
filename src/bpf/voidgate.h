
/* SPDX-License-Identifier: Apache-2.0
 * Shared types for the XDP program and userspace. Keep this header
 * free of libc and kernel-only APIs so both sides can include it.
 */

#ifndef _VG_VOIDGATE_H_INCLUDED_
#define _VG_VOIDGATE_H_INCLUDED_

#include <linux/types.h>

#define VG_SOCK_PATH  "/run/voidgate.sock"

#define VG_MAX_ALLOW_PORTS  8

#define VG_DROP_MAP_MAX  65536
#define VG_REMOTE_MAP_MAX  262144
#define VG_HOST_MAP_MAX  1024
#define VG_LPM_MAP_MAX  4096

#define VG_REASON_MANUAL  1
#define VG_REASON_POLICY  2
#define VG_REASON_AGGREGATE  3
#define VG_REASON_TIMED  4

/* ICMPv6 NDP types (RFC 4861), which uapi doesn't define */
#define VG_NDISC_RS  133
#define VG_NDISC_RA  134
#define VG_NDISC_NS  135
#define VG_NDISC_NA  136
#define VG_NDISC_REDIRECT  137
#define VG_NDISC_HOP_LIMIT  255

struct host_counters {
    __u64  in_pkts;
    __u64  in_bytes;
};


/* Per-CPU; userspace sums CPUs in vg_metrics_read. */
struct vg_metrics {
    __u64  rx_pkts;    /* packets seen, idle and armed */
    __u64  rx_bytes;   /* L2 bytes of rx_pkts */
    __u64  passed;     /* passed via pass(); not parse_fail */
    __u64  dropped;    /* dropped by the drop LPM */
    __u64  non_ip;     /* armed, not IPv4/IPv6 */
    __u64  map_full;   /* host/remote hash insert failed */
    __u64  parse_err;  /* bad header; still judged by the drop LPM when
                          both addresses are readable, else passed */
    __u64  reply_passed;  /* armed, a reply to a flow the host opened:
                             passed, not counted against its source */
};


struct vg_cfg {
    __u32  armed;
    __u16  allow_ports[VG_MAX_ALLOW_PORTS];
    __u16  allow_port_count;
    __u64  reply_idle_ns;  /* a flow idle longer is not looked up */
};


struct drop_entry {
    __u32  reason;
    __u32  insert_time;
};


struct vg_lpm_v4 {
    __u32  prefixlen;
    __u8   data[4];
};


struct vg_lpm_v6 {
    __u32  prefixlen;
    __u8   data[16];
};


struct vg_ip6 {
    __u8 addr[16];
};

#endif /* _VG_VOIDGATE_H_INCLUDED_ */
