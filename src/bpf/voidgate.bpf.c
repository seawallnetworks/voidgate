// SPDX-License-Identifier: GPL-2.0-only
/* voidgate data plane.
 *
 * IDLE (cfg.armed == 0, or no cfg):
 *   every frame                                 → count rx and passed, PASS
 *   nothing is parsed or looked up.
 *
 * ACTIVE (cfg.armed == 1), first match wins:
 *   1. whitelist                                → count, PASS
 *   2. reply to a flow the host opened, found
 *      in sw_flowd's table (Seawall 0007)       → PASS, source not counted
 *   3. source or destination in drop LPM        → DROP
 *   4. anything else                            → count, PASS
 *
 * Control plane decides prefixes; this program only enforces them.
 *
 * Two entries share vg_judge(): voidgate_xdp, run by libxdp's dispatcher,
 * and voidgate_tc, at TC ingress when another program holds the XDP hook.
 * The loader loads one of them.
 */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <xdp/xdp_helpers.h>
#include "voidgate.h"
#include <libpkt/parse.h>
#include <sw_flowd/sw_flowd.h>

/* vg_judge()'s verdict; each entry turns it into its hook's. */
#define VG_PASS  0
#define VG_DROP  1


static __always_inline struct vg_metrics *get_metrics(void);
static __always_inline struct vg_cfg *get_cfg(void);
static __always_inline int port_allowed(const struct vg_cfg *c, __u16 port);
static __always_inline int v4_in_lpm(void *map, __be32 ip);
static __always_inline int v6_in_lpm(void *map, const __u8 addr[16]);
static __always_inline int v6_is_linklocal(const __u8 addr[16]);
static __always_inline int v6_is_mcast_link(const __u8 addr[16]);
static __always_inline void acc_in(struct host_counters *c, __u64 pkts,
    __u64 bytes);
static __always_inline int v4_dhcp_allowed(__be32 daddr, __u16 sport,
    __u16 dport);
static __always_inline int v6_dhcp_allowed(const __u8 daddr[16],
    __u16 sport, __u16 dport);
static __always_inline int v4_tcp_allowed(const struct vg_cfg *c,
    __be32 saddr, __be32 daddr, __u16 sport, __u16 dport);
static __always_inline int v6_tcp_allowed(const struct vg_cfg *c,
    const __u8 saddr[16], const __u8 daddr[16], __u16 sport, __u16 dport);
static __always_inline int v6_hop_limit(void *data, void *data_end,
    __u16 l3_off);
static __always_inline int is_reply(const struct vg_cfg *c,
    __u8 family, __u8 proto, const void *saddr, __u16 sport, __u16 dport,
    __u8 tcp_flags);
static __always_inline int pass(struct vg_metrics *m, __u64 pkts);
static __always_inline int parse_fail(struct vg_metrics *m);

/* Userspace ARRAY[1]: armed and allow_ports. XDP reads. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct vg_cfg);
} cfg SEC(".maps");


/* Per-CPU ARRAY[1]: rx_* always; drop/pass and the rest only when armed. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct vg_metrics);
} metrics SEC(".maps");


/* LPM of IPv4 prefixes to drop. ACTIVE write; flushed on disarm. */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, VG_DROP_MAP_MAX);
    __type(key, struct vg_lpm_v4);
    __type(value, struct drop_entry);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} drop_v4 SEC(".maps");


/* LPM of IPv6 prefixes to drop. ACTIVE write; flushed on disarm. */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, VG_DROP_MAP_MAX);
    __type(key, struct vg_lpm_v6);
    __type(value, struct drop_entry);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} drop_v6 SEC(".maps");


/* LPM of IPv4 never-drop CIDRs. Userspace at start/reload. */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, VG_LPM_MAP_MAX);
    __type(key, struct vg_lpm_v4);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} allow_v4 SEC(".maps");


/* LPM of IPv6 never-drop CIDRs. Userspace at start/reload. */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, VG_LPM_MAP_MAX);
    __type(key, struct vg_lpm_v6);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} allow_v6 SEC(".maps");


/* LPM of this VM's IPv4 CIDRs; dest/src-local and TCP allow-port. */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, VG_LPM_MAP_MAX);
    __type(key, struct vg_lpm_v4);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} local_v4 SEC(".maps");


/* LPM of this VM's IPv6 CIDRs; dest/src-local and TCP allow-port. */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, VG_LPM_MAP_MAX);
    __type(key, struct vg_lpm_v6);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} local_v6 SEC(".maps");


/* Per-CPU hash of local IPv4 dests; inbound volume when dest is local. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, VG_HOST_MAP_MAX);
    __type(key, __be32);
    __type(value, struct host_counters);
} host_v4 SEC(".maps");


/* Per-CPU hash of local IPv6 dests; inbound volume when dest is local. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, VG_HOST_MAP_MAX);
    __type(key, struct vg_ip6);
    __type(value, struct host_counters);
} host_v6 SEC(".maps");


/* LRU per-CPU hash of dest-local IPv4 sources; not flushed on disarm. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, VG_REMOTE_MAP_MAX);
    __type(key, __be32);
    __type(value, struct host_counters);
} remote_v4 SEC(".maps");


/* LRU per-CPU hash of dest-local IPv6 sources; not flushed on disarm. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, VG_REMOTE_MAP_MAX);
    __type(key, struct vg_ip6);
    __type(value, struct host_counters);
} remote_v6 SEC(".maps");


/* sw_flowd's flow table and its config (Seawall proposal 0009): userspace
 * binds their pinned maps here before the load (bpf_map__reuse_fd), with
 * the table's size sw_flowd's. Without them, these are voidgate's own and
 * stay empty: no flow, as before sw_flowd.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1);
    __type(key, struct sf_flow_key);
    __type(value, struct sf_flow);
} flows SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct sf_config);
} flows_config SEC(".maps");


static __always_inline struct vg_metrics *
get_metrics(void)
{
    __u32 key = 0;

    return bpf_map_lookup_elem(&metrics, &key);
}


static __always_inline struct vg_cfg *
get_cfg(void)
{
    __u32 key = 0;

    return bpf_map_lookup_elem(&cfg, &key);
}


static __always_inline int
port_allowed(const struct vg_cfg *c, __u16 port)
{
    int i;

    if (c == NULL) {
        return 0;
    }

#pragma unroll
    for (i = 0; i < VG_MAX_ALLOW_PORTS; i++) {
        if (i >= c->allow_port_count) {
            break;
        }

        if (c->allow_ports[i] == port) {
            return 1;
        }
    }

    return 0;
}


static __always_inline int
v4_in_lpm(void *map, __be32 ip)
{
    struct vg_lpm_v4 key = {};

    key.prefixlen = 32;
    __builtin_memcpy(key.data, &ip, 4);

    return bpf_map_lookup_elem(map, &key) != NULL;
}


static __always_inline int
v6_in_lpm(void *map, const __u8 addr[16])
{
    struct vg_lpm_v6 key = {};

    key.prefixlen = 128;
    __builtin_memcpy(key.data, addr, 16);

    return bpf_map_lookup_elem(map, &key) != NULL;
}


static __always_inline int
v6_is_linklocal(const __u8 addr[16])
{
    return addr[0] == 0xfe && (addr[1] & 0xc0) == 0x80;
}


static __always_inline int
v6_is_mcast_link(const __u8 addr[16])
{
    return addr[0] == 0xff && addr[1] == 0x02;
}

#define VG_HASH_GET(map, keyp, m) \
    ({ \
        struct host_counters *_c; \
        struct host_counters _zero = {}; \
        _c = bpf_map_lookup_elem(&(map), (keyp)); \
        \
        if (_c == NULL) { \
            bpf_map_update_elem(&(map), (keyp), &_zero, BPF_NOEXIST); \
            _c = bpf_map_lookup_elem(&(map), (keyp)); \
            \
            if (_c == NULL && (m) != NULL) { \
                (m)->map_full++; \
            } \
        } \
        \
        _c; \
    })

static __always_inline void
acc_in(struct host_counters *c, __u64 pkts, __u64 bytes)
{
    if (c == NULL) {
        return;
    }

    c->in_pkts += pkts;
    c->in_bytes += bytes;
}


/* Allow DHCP only as an exact client/server port pair aimed at this VM.
 * Client: server or relay 67 -> 68. Server: client 68 or relay 67 -> 67.
 * Dest must be local or 255.255.255.255 (no lease yet). A remote source
 * port of 67/68 alone is not a whitelist hit.
 */
static __always_inline int
v4_dhcp_allowed(__be32 daddr, __u16 sport, __u16 dport)
{
    if (!((dport == 68 && sport == 67)
          || (dport == 67 && (sport == 68 || sport == 67))))
    {
        return 0;
    }

    return daddr == 0xffffffff || v4_in_lpm(&local_v4, daddr);
}


/* DHCPv6 client: server 547 -> 546. Server: client 546 or relay 547 -> 547.
 * Link-local and ff02:: dests already pass; here dest must be local.
 */
static __always_inline int
v6_dhcp_allowed(const __u8 daddr[16], __u16 sport, __u16 dport)
{
    if (!((dport == 546 && sport == 547)
          || (dport == 547 && (sport == 546 || sport == 547))))
    {
        return 0;
    }

    return v6_in_lpm(&local_v6, daddr);
}


/* Allow TCP only when the local side is the configured service port.
 * Inbound SSH: dport 22 and dest is this VM. Replies we originated that
 * appear on ingress: sport 22 and src is local. A remote sport=22 flood
 * is not a whitelist hit.
 */
static __always_inline int
v4_tcp_allowed(const struct vg_cfg *c,
    __be32 saddr, __be32 daddr,
    __u16 sport, __u16 dport)
{
    if (port_allowed(c, dport) && v4_in_lpm(&local_v4, daddr)) {
        return 1;
    }

    if (port_allowed(c, sport) && v4_in_lpm(&local_v4, saddr)) {
        return 1;
    }

    return 0;
}


static __always_inline int
v6_tcp_allowed(const struct vg_cfg *c,
    const __u8 saddr[16],
    const __u8 daddr[16], __u16 sport,
    __u16 dport)
{
    if (port_allowed(c, dport) && v6_in_lpm(&local_v6, daddr)) {
        return 1;
    }

    if (port_allowed(c, sport) && v6_in_lpm(&local_v6, saddr)) {
        return 1;
    }

    return 0;
}


/* The hop limit of the IPv6 header at l3_off, which pkt_meta does not
 * keep; 0 if it is not there.
 */
static __always_inline int
v6_hop_limit(void *data, void *data_end, __u16 l3_off)
{
    struct ipv6hdr *ip6;

    if (l3_off > PKT_L2_MAX) {
        return 0;
    }

    ip6 = data + l3_off;

    if ((void *) (ip6 + 1) > data_end) {
        return 0;
    }

    return ip6->hop_limit;
}


/* Is this packet to a local address a reply to a flow the host opened:
 * one sw_flowd recorded leaving within reply_idle_ns? Only what can
 * be a reply is looked up: TCP with ACK (a reply is a SYN-ACK or later),
 * UDP to a port in the ephemeral range sw_flowd records UDP from. Other
 * protocols are never recorded, so their lookup misses.
 */
static __always_inline int
is_reply(const struct vg_cfg *c, __u8 family, __u8 proto,
    const void *saddr, __u16 sport, __u16 dport, __u8 tcp_flags)
{
    struct sf_config *fc;
    __u64 seen;
    __u32 zero = 0;

    if (proto == IPPROTO_TCP && !(tcp_flags & PKT_TCP_ACK)) {
        return 0;
    }

    if (proto == IPPROTO_UDP) {
        fc = bpf_map_lookup_elem(&flows_config, &zero);

        if (fc == NULL || dport < fc->port_lo || dport > fc->port_hi) {
            return 0;
        }
    }

    seen = sf_flow_seen(&flows, family, proto, saddr, sport, dport);

    if (seen == 0) {
        return 0;
    }

    return bpf_ktime_get_coarse_ns() - seen < c->reply_idle_ns;
}


static __always_inline int
pass(struct vg_metrics *m, __u64 pkts)
{
    if (m != NULL) {
        m->passed += pkts;
    }

    return VG_PASS;
}


static __always_inline int
parse_fail(struct vg_metrics *m)
{
    if (m != NULL) {
        m->parse_err++;
    }

    return VG_PASS;
}


/* An armed gate's verdict on the frame at data: pkts packets (more than
 * one for a GRO'd skb at TC) of pkt_len bytes in all.
 *
 * What libpkt's parse reached decides what is judged: not IP, passed;
 * no addresses, passed uncounted; addresses with no trustworthy L4 (a bad
 * or truncated header), counted in parse_err and judged without ports,
 * so the drop LPM still applies and the port exemptions cannot; a
 * non-first fragment or another protocol, judged without ports.
 *
 * The ports, TCP flags and ICMPv6 type are read on PKT_OK only, and are 0
 * otherwise, as libpkt leaves them: read whatever the status, clang
 * stored them again before each of the parse's early returns, which cost
 * IPv4 4-11 ns a frame.
 */
static __always_inline int
vg_judge(void *data, void *data_end, struct vg_cfg *c, struct vg_metrics *m,
    __u64 pkts, __u64 pkt_len)
{
    struct pkt_meta pm;
    __u16 sport, dport;
    __u8 tcp_flags, icmp6_type;
    int rc, local = -1;

    rc = pkt_parse(data, data_end, &pm);

    if (rc == PKT_NOT_IP) {
        if (m != NULL) {
            m->non_ip++;
        }

        return pass(m, pkts);
    }

    if (pm.family == 0) {
        return parse_fail(m);
    }

    if (rc == PKT_OK) {
        sport = bpf_ntohs(pm.sport);
        dport = bpf_ntohs(pm.dport);
        tcp_flags = pm.tcp_flags;
        icmp6_type = pm.icmp6_type;

    } else {
        sport = 0;
        dport = 0;
        tcp_flags = 0;
        icmp6_type = 0;

        if (rc != PKT_NO_L4 && m != NULL) {
            m->parse_err++;
        }
    }

    if (pm.family == PKT_V4) {
        __be32 saddr, daddr;

        __builtin_memcpy(&saddr, pm.addr_src, 4);
        __builtin_memcpy(&daddr, pm.addr_dst, 4);

        if (v4_in_lpm(&allow_v4, saddr) || v4_in_lpm(&allow_v4, daddr)) {
            goto v4_count;
        }

        if (pm.l4_proto == IPPROTO_TCP
            && v4_tcp_allowed(c, saddr, daddr, sport, dport))
        {
            goto v4_count;
        }

        if (pm.l4_proto == IPPROTO_UDP
            && v4_dhcp_allowed(daddr, sport, dport))
        {
            goto v4_count;
        }

        local = v4_in_lpm(&local_v4, daddr);

        /* not counted against its source, which it would get banned */
        if (local && is_reply(c, SF_FAMILY_V4, pm.l4_proto, &saddr, sport,
                              dport, tcp_flags))
        {
            acc_in(VG_HASH_GET(host_v4, &daddr, m), pkts, pkt_len);

            if (m != NULL) {
                m->reply_passed += pkts;
            }

            return pass(m, pkts);
        }

        if (v4_in_lpm(&drop_v4, saddr) || v4_in_lpm(&drop_v4, daddr)) {
            if (m != NULL) {
                m->dropped += pkts;
            }

            return VG_DROP;
        }


        v4_count:

        if (local < 0) {
            local = v4_in_lpm(&local_v4, daddr);
        }

        if (local) {
            acc_in(VG_HASH_GET(host_v4, &daddr, m), pkts, pkt_len);
            acc_in(VG_HASH_GET(remote_v4, &saddr, m), pkts, pkt_len);
        }

        return pass(m, pkts);
    }

    /* PKT_V6 */
    {
        struct vg_ip6 saddr, daddr;

        /* copied out of pm, not looked up from it in place: so the
         * verifier merges the parse's paths, and walks 33,000
         * instructions, not 194,000
         */
        __builtin_memcpy(saddr.addr, pm.addr_src, 16);
        __builtin_memcpy(daddr.addr, pm.addr_dst, 16);

        if (v6_is_linklocal(saddr.addr) || v6_is_linklocal(daddr.addr)
            || v6_is_mcast_link(saddr.addr) || v6_is_mcast_link(daddr.addr))
        {
            goto v6_count;
        }

        /* RFC 4861: real NDP is sent with hop limit 255 and the kernel drops
         * anything else, so a routed NS/RA flood cannot use this exemption.
         */
        if (icmp6_type >= VG_NDISC_RS && icmp6_type <= VG_NDISC_REDIRECT
            && v6_hop_limit(data, data_end, pm.l3_off) == VG_NDISC_HOP_LIMIT)
        {
            goto v6_count;
        }

        if (v6_in_lpm(&allow_v6, saddr.addr)
            || v6_in_lpm(&allow_v6, daddr.addr))
        {
            goto v6_count;
        }

        if (pm.l4_proto == IPPROTO_TCP
            && v6_tcp_allowed(c, saddr.addr, daddr.addr, sport, dport))
        {
            goto v6_count;
        }

        if (pm.l4_proto == IPPROTO_UDP
            && v6_dhcp_allowed(daddr.addr, sport, dport))
        {
            goto v6_count;
        }

        local = v6_in_lpm(&local_v6, daddr.addr);

        if (local && is_reply(c, SF_FAMILY_V6, pm.l4_proto, saddr.addr, sport,
                              dport, tcp_flags))
        {
            acc_in(VG_HASH_GET(host_v6, &daddr, m), pkts, pkt_len);

            if (m != NULL) {
                m->reply_passed += pkts;
            }

            return pass(m, pkts);
        }

        if (v6_in_lpm(&drop_v6, saddr.addr)
            || v6_in_lpm(&drop_v6, daddr.addr))
        {
            if (m != NULL) {
                m->dropped += pkts;
            }

            return VG_DROP;
        }


        v6_count:

        if (local < 0) {
            local = v6_in_lpm(&local_v6, daddr.addr);
        }

        if (local) {
            acc_in(VG_HASH_GET(host_v6, &daddr, m), pkts, pkt_len);
            acc_in(VG_HASH_GET(remote_v6, &saddr, m), pkts, pkt_len);
        }

        return pass(m, pkts);
    }
}


static __always_inline void
rx_count(struct vg_metrics *m, __u64 pkts, __u64 bytes)
{
    if (m != NULL) {
        m->rx_pkts += pkts;
        m->rx_bytes += bytes;
    }
}


/* libxdp's dispatcher runs voidgate ahead of mini-fw (priority 20), and
 * only a pass goes on to the next program. Frags: the headers are in the
 * first buffer, so a jumbo-MTU interface keeps the dispatcher.
 */
struct {
    __uint(priority, 10);
    __uint(XDP_PASS, 1);
} XDP_RUN_CONFIG(voidgate_xdp);

SEC("xdp.frags")
int
voidgate_xdp(struct xdp_md *ctx)
{
    void *data = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;
    struct vg_metrics *m = get_metrics();
    struct vg_cfg *c;
    __u64 pkt_len = bpf_xdp_get_buff_len(ctx);

    rx_count(m, 1, pkt_len);

    c = get_cfg();

    if (c == NULL || c->armed == 0) {
        pass(m, 1);
        return XDP_PASS;
    }

    if (vg_judge(data, data_end, c, m, 1, pkt_len) == VG_DROP) {
        return XDP_DROP;
    }

    return XDP_PASS;
}


/* Pass is TC_ACT_UNSPEC, which is tcx's TCX_NEXT: classic TC and tcx both
 * go on to the next program, mini-fw's. A GRO'd skb counts as its
 * segments, as XDP saw them.
 */
SEC("tc")
int
voidgate_tc(struct __sk_buff *ctx)
{
    struct vg_metrics *m = get_metrics();
    struct vg_cfg *c;
    void *data, *data_end;
    __u64 pkts = ctx->gso_segs ? ctx->gso_segs : 1;
    __u32 want;

    rx_count(m, pkts, ctx->len);

    c = get_cfg();

    if (c == NULL || c->armed == 0) {
        pass(m, pkts);
        return TC_ACT_UNSPEC;
    }

    /* A TC program reads only the skb's linear part, which may hold just
     * the Ethernet header. Pull only when it is short of PKT_HDR_MAX, the
     * most libpkt reads: a pull makes the skb writable, copying a cloned
     * skb's head. One that fails leaves the short view, judged without
     * ports, like a truncated header.
     */
    data = (void *) (long) ctx->data;
    data_end = (void *) (long) ctx->data_end;
    want = ctx->len < PKT_HDR_MAX ? ctx->len : PKT_HDR_MAX;

    if (data + want > data_end) {
        bpf_skb_pull_data(ctx, want);
        data = (void *) (long) ctx->data;
        data_end = (void *) (long) ctx->data_end;
    }

    if (vg_judge(data, data_end, c, m, pkts, ctx->len) == VG_DROP) {
        return TC_ACT_SHOT;
    }

    return TC_ACT_UNSPEC;
}


char LICENSE[] SEC("license") = "GPL";
