
/* SPDX-License-Identifier: Apache-2.0
 * Shared types for the XDP program and userspace. Keep this header
 * free of libc and kernel-only APIs so both sides can include it.
 */

#ifndef _VG_VOIDGATE_H_INCLUDED_
#define _VG_VOIDGATE_H_INCLUDED_

#include <linux/types.h>

#define VG_SOCK_PATH  "/run/voidgate.sock"
/* read-only: status, stats, feed, blocks (Seawall proposal 0012) */
#define VG_MONITOR_SOCK_PATH  "/run/voidgate-monitor.sock"
#define VG_BAN_SOCK_PATH      "/run/voidgate-ban.sock"

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
    __u64  passed;     /* passed, idle or judged; not one with no
                          addresses, in parse_err only */
    __u64  dropped;    /* dropped by the drop LPM */
    __u64  non_ip;     /* armed, not IPv4/IPv6 */
    __u64  map_full;   /* host/remote hash insert failed */
    __u64  parse_err;  /* bad header; still judged by the drop LPM when
                          both addresses are readable, else passed */
    __u64  reply_passed;  /* armed, a reply to a flow the host opened:
                             passed, not counted against its source */
    __u64  rx_reply_pkts;   /* of rx_pkts, replies to a flow the host
                               opened, idle and armed, whatever the
                               verdict; 0 without sw_flowd's table.
                               rx less these is what wakes the gate
                               (Seawall proposal 0017 §1) */
    __u64  rx_reply_bytes;  /* L2 bytes of rx_reply_pkts */
    /* first-SYN drop (Seawall proposal 0023), syn_guard = yes, armed */
    __u64  syn_unproven;    /* SYNs from unproven addresses, before the
                               filter, engaged or not; not those the drop
                               LPM drops first. What engages it */
    __u64  syn_guard_dropped;  /* first SYNs dropped */
    __u64  syn_guard_retrans;  /* found in an older generation: passed
                                  on to the checks after it */
    __u64  syn_guard_unready;  /* the current slot not cleared in time:
                                  passed on unfiltered */
};


struct vg_cfg {
    __u32  armed;
    __u16  allow_ports[VG_MAX_ALLOW_PORTS];
    __u16  allow_port_count;
    __u64  reply_idle_ns;  /* a flow idle longer is not looked up */
    __u32  flows;          /* sw_flowd's table is bound: replies are
                              looked up, idle too */
    __u32  syn_guard;      /* syn_guard = yes: pure SYNs aren't counted
                              against their source, and are counted in
                              syn_unproven */
    __u32  syn_engaged;    /* first-SYN drop drops: userspace decides */
};


/*
 * First-SYN drop's generational Bloom filter (Seawall proposal 0023 §2).
 * A generation is VG_SYN_GEN_NS of bpf_ktime_get_coarse_ns(),
 * CLOCK_MONOTONIC_COARSE (bpf_ktime_get_ns() in the plain entries);
 * generation g lives in slot g % VG_SYN_SLOTS, and a SYN is looked up in
 * the current one and VG_SYN_OLDER before it. One 64-byte block, a cache
 * line, is one element of syn_bloom: slot * blocks + block.
 */
#define VG_SYN_GEN_NS  900000000ULL
#define VG_SYN_OLDER  4
#define VG_SYN_SLOTS  6
#define VG_SYN_BLOCK_BITS  512
#define VG_SYN_BLOCK_LOG2  9
#define VG_SYN_BITS_MIN  23
#define VG_SYN_BITS_MAX  28
/* a slot no generation has been cleared into: never one from the clock */
#define VG_SYN_MARK_NONE  ((__u64) -1)


struct vg_syn_block {
    __u64  w[VG_SYN_BLOCK_BITS / 64];
};


/* syn_marks' one element: the generation each slot was cleared for.
 * Written by userspace alone, through mmap, with release.
 */
struct vg_syn_marks {
    __u64  gen[8];          /* VG_SYN_SLOTS used: one cache line */
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
