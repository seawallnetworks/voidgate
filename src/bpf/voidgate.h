
/* SPDX-License-Identifier: Apache-2.0
 * Shared types for the XDP program and userspace. Keep this header
 * free of libc and kernel-only APIs so both sides can include it.
 */

#ifndef _VG_VOIDGATE_H_INCLUDED_
#define _VG_VOIDGATE_H_INCLUDED_

#include <linux/types.h>

#define VG_SOCK_PATH  "/run/voidgate.sock"

#define VG_MAX_ALLOW_PORTS  8
#define VG_MAX_VLANS  2
#define VG_MAX_IPV6_EXT  8

#define VG_DROP_MAP_MAX  65536
#define VG_REMOTE_MAP_MAX  262144
#define VG_HOST_MAP_MAX  1024
#define VG_LPM_MAP_MAX  4096

#define VG_REASON_MANUAL  1
#define VG_REASON_POLICY  2
#define VG_REASON_AGGREGATE  3
#define VG_REASON_TIMED  4

#define VG_IPPROTO_TCP  6
#define VG_IPPROTO_UDP  17
#define VG_IPPROTO_ICMP  1
#define VG_IPPROTO_ICMPV6  58
#define VG_IPPROTO_FRAGMENT  44
#define VG_IPPROTO_HOPOPTS  0
#define VG_IPPROTO_ROUTING  43
#define VG_IPPROTO_AH  51
#define VG_IPPROTO_DSTOPTS  60

#define VG_ETH_P_IP  0x0800
#define VG_ETH_P_IPV6  0x86dd
#define VG_ETH_P_8021Q  0x8100
#define VG_ETH_P_8021AD  0x88a8

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


struct vg_eth {
    __u8    dst[6];
    __u8    src[6];
    __be16  proto;
} __attribute__((packed));

struct vg_vlan {
    __be16  tci;
    __be16  proto;
} __attribute__((packed));

struct vg_iphdr {
    __u8    ver_ihl;
    __u8    tos;
    __be16  tot_len;
    __be16  id;
    __be16  frag_off;
    __u8    ttl;
    __u8    protocol;
    __be16  check;
    __be32  saddr;
    __be32  daddr;
} __attribute__((packed));

struct vg_ipv6hdr {
    __u8    ver_tc;
    __u8    flow[3];
    __be16  payload_len;
    __u8    nexthdr;
    __u8    hop_limit;
    __u8    saddr[16];
    __u8    daddr[16];
} __attribute__((packed));

struct vg_ip6_frag {
    __u8    nexthdr;
    __u8    res;
    __be16  frag_off;
    __be32  id;
} __attribute__((packed));

struct vg_tcphdr {
    __be16  source;
    __be16  dest;
    __be32  seq;
    __be32  ack_seq;
    __u8    doff_res;
    __u8    flags;
    __be16  window;
    __be16  check;
    __be16  urg_ptr;
} __attribute__((packed));

struct vg_udphdr {
    __be16  source;
    __be16  dest;
    __be16  len;
    __be16  check;
} __attribute__((packed));

struct vg_icmpv6hdr {
    __u8    type;
    __u8    code;
    __be16  checksum;
} __attribute__((packed));

#endif /* _VG_VOIDGATE_H_INCLUDED_ */
