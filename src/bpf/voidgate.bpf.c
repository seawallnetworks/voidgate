// SPDX-License-Identifier: GPL-2.0-only
/* voidgate data plane.
 *
 * IDLE (cfg.armed == 0, or no cfg):
 *   every frame                                 → count rx and passed, PASS
 *   nothing else is judged. With sw_flowd's table bound (cfg.flows), each
 *   frame is parsed and looked up there too, only to count the replies to
 *   the host's own flows, which don't wake the gate (Seawall 0017 §1);
 *   without it, nothing is parsed or looked up.
 *
 * Both states count those replies in rx_reply_*, whatever the verdict.
 *
 * ACTIVE (cfg.armed == 1), first match wins:
 *   1. allow_networks                           → count, PASS
 *   2. a pure SYN, syn_guard = yes (Seawall 0023), never counted against
 *      its source: to a port not in allow_ports, from or to the drop LPM
 *      → DROP; then, engaged, a first SYN → DROP; else on to 3
 *   3. allow_ports, DHCP                        → count, PASS
 *   4. reply to a flow the host opened, found
 *      in sw_flowd's table (Seawall 0015)       → PASS, source not counted
 *   5. source or destination in drop LPM        → DROP
 *   6. anything else                            → count, PASS
 *
 * The control plane decides policy, what to block and when first-SYN drop
 * engages; this program carries out the per-packet mechanisms: the drop
 * LPM, the first-SYN filter.
 *
 * Two entries share vg_judge(): voidgate_xdp, run by libxdp's dispatcher,
 * and voidgate_tc, at TC ingress when another program holds the XDP hook.
 * Each has a twin, voidgate_xdp_pl and voidgate_tc_pl, that sets the
 * Bloom filter's bits with a plain write, for a kernel before 5.12, whose
 * verifier refuses an atomic OR even where it is never run, and reads
 * bpf_ktime_get_ns(), not the coarse clock (5.11+). The loader loads one
 * of the four.
 */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <xdp/xdp_helpers.h>
#include "voidgate.h"
#include <libpkt/parse.h>
/* sw_flowd's ICMP error check, SF_DEFINE_ICMP_ERR_REPLY() */
#define SF_ICMP_ERR_REPLY
#include <sw_flowd/sw_flowd.h>

/* vg_judge()'s verdict; each entry turns it into its hook's. */
#define VG_PASS  0
#define VG_DROP  1

/* which entry vg_judge() runs in: a constant, so each keeps its own call */
#define VG_HOOK_XDP  0
#define VG_HOOK_TC   1

/* what the first-SYN filter found (Seawall proposal 0023 §2) */
#define VG_SYN_DROP  0      /* a first SYN, remembered */
#define VG_SYN_RETRANS  1   /* in an older generation */
#define VG_SYN_UNREADY  2   /* the current slot not cleared: fail-open */

#define VG_ROTL(x, b)  (((x) << (b)) | ((x) >> (64 - (b))))

/* one SipHash round on v0..v3 */
#define VG_SIPROUND(v0, v1, v2, v3)                                         \
    do {                                                                    \
        v0 += v1; v1 = VG_ROTL(v1, 13); v1 ^= v0; v0 = VG_ROTL(v0, 32);     \
        v2 += v3; v3 = VG_ROTL(v3, 16); v3 ^= v2;                           \
        v0 += v3; v3 = VG_ROTL(v3, 21); v3 ^= v0;                           \
        v2 += v1; v1 = VG_ROTL(v1, 17); v1 ^= v2; v2 = VG_ROTL(v2, 32);     \
    } while (0)

/* SipHash-1-3: one compression round a word */
#define VG_SIPWORD(v0, v1, v2, v3, m)                                       \
    do {                                                                    \
        v3 ^= (m);                                                          \
        VG_SIPROUND(v0, v1, v2, v3);                                        \
        v0 ^= (m);                                                          \
    } while (0)


/* Set by userspace before the load: the hash's key, drawn at each start,
 * and log2 of the blocks in a generation, syn_guard_bits less 9.
 */
const volatile __u64 vg_syn_k0 = 0;
const volatile __u64 vg_syn_k1 = 0;
const volatile __u32 vg_syn_blocks_log2 = 16;


static __always_inline struct vg_metrics *get_metrics(void);
static __always_inline struct vg_cfg *get_cfg(void);
static __always_inline int port_allowed(const struct vg_cfg *c, __u16 port);
static __always_inline int v4_in_lpm(void *map, __be32 ip);
static __always_inline int v6_in_lpm(void *map, const __u8 addr[16]);
static __always_inline int v6_is_linklocal(const __u8 addr[16]);
static __always_inline int v6_is_mcast_link(const __u8 addr[16]);
static __always_inline void host_count_in(struct host_counters *c, __u64 pkts,
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
static __always_inline int is_reply(const struct vg_cfg *c, int rc,
    const struct pkt_meta *pm, void *ctx, int hook);
static __always_inline void reply_count(struct vg_metrics *m, __u64 pkts,
    __u64 bytes);
static __always_inline void idle_replies(void *data, void *data_end,
    const struct vg_cfg *c, struct vg_metrics *m, __u64 pkts,
    __u64 pkt_len, void *ctx, int hook);

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


/* sw_flowd's flow table and its config (Seawall proposal 0015): userspace
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


/* First-SYN drop's Bloom filter (Seawall proposal 0023 §2): VG_SYN_SLOTS
 * slots of 2^vg_syn_blocks_log2 blocks, sized by userspace before the
 * load, which zeroes a slot through mmap before its generation begins.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct vg_syn_block);
    __uint(map_flags, BPF_F_MMAPABLE);
} syn_bloom SEC(".maps");


/* The generation each slot was cleared for: userspace writes, BPF reads. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct vg_syn_marks);
    __uint(map_flags, BPF_F_MMAPABLE);
} syn_marks SEC(".maps");


/* sw_flowd's ICMP error check on the table, for each entry: global
 * functions, which the verifier walks once, not once a path (sw_flowd.h)
 */
SF_DEFINE_ICMP_ERR_REPLY(vg_icmp_err_xdp, struct xdp_md, flows)
SF_DEFINE_ICMP_ERR_REPLY(vg_icmp_err_tc, struct __sk_buff, flows)


/*
 * SipHash-1-3 of a SYN's key, with the key drawn at start (Seawall
 * proposal 0023 §2). A global function, verified once, not on each path
 * that calls it.
 */
__noinline __u64
vg_syn_hash(__u64 m0, __u64 m1, __u64 m2, __u64 m3, __u64 m4)
{
    __u64 k0 = vg_syn_k0, k1 = vg_syn_k1;
    __u64 v0 = k0 ^ 0x736f6d6570736575ULL;
    __u64 v1 = k1 ^ 0x646f72616e646f6dULL;
    __u64 v2 = k0 ^ 0x6c7967656e657261ULL;
    __u64 v3 = k1 ^ 0x7465646279746573ULL;
    __u64 b = 40ULL << 56;

    VG_SIPWORD(v0, v1, v2, v3, m0);
    VG_SIPWORD(v0, v1, v2, v3, m1);
    VG_SIPWORD(v0, v1, v2, v3, m2);
    VG_SIPWORD(v0, v1, v2, v3, m3);
    VG_SIPWORD(v0, v1, v2, v3, m4);
    VG_SIPWORD(v0, v1, v2, v3, b);

    v2 ^= 0xff;
    VG_SIPROUND(v0, v1, v2, v3);
    VG_SIPROUND(v0, v1, v2, v3);
    VG_SIPROUND(v0, v1, v2, v3);

    return v0 ^ v1 ^ v2 ^ v3;
}


/* Generation g's slot. The mask, which clang can't drop as redundant
 * behind the barrier, bounds it for the verifier, which doesn't learn
 * one from a modulo.
 */
static __always_inline __u32
syn_slot(__u64 g)
{
    __u32 slot = (__u32) (g % VG_SYN_SLOTS);

    barrier_var(slot);

    return slot & 7;
}


static __always_inline int
syn_bit(const struct vg_syn_block *b, __u32 o)
{
    return (b->w[(o >> 6) & 7] >> (o & 63)) & 1;
}


/*
 * Bit o of b set, read first: a set bit isn't written, so a line every
 * CPU reads isn't made to bounce. With atomic, an atomic OR, which keeps
 * another CPU's bit set in the same word at once; without, for a kernel
 * before 5.12, a plain write, which may lose it: a real client's first
 * retransmission is dropped too, never all of them.
 */
static __always_inline void
syn_set(struct vg_syn_block *b, __u32 o, int atomic)
{
    __u64 bit = 1ULL << (o & 63);
    __u32 w = (o >> 6) & 7;

    if (b->w[w] & bit) {
        return;
    }

    /*
     * The atomic OR as asm: clang emits one only at -mcpu=v3, whose
     * 32-bit subregisters double what the verifier walks in vg_judge()
     */
    if (atomic) {
        asm volatile("lock *(u64 *)(%0 + 0) |= %1"
                     :: "r" (&b->w[w]), "r" (bit) : "memory");

    } else {
        b->w[w] |= bit;
    }
}


/*
 * The generational Bloom filter (Seawall proposal 0023 §2) on a SYN's
 * hash h: its block from the low bits, three bit offsets in it from the
 * 27 above. Found in one of the VG_SYN_OLDER generations before the
 * current one, whose slot was cleared for it: a retransmission. Else
 * written into the current generation: a first SYN, dropped. The current
 * slot not cleared for this generation: passed unfiltered.
 */
static __always_inline int
syn_filter(__u64 h, int atomic)
{
    struct vg_syn_marks *mk;
    struct vg_syn_block *b;
    __u64 g, gi;
    __u32 key = 0, log2 = vg_syn_blocks_log2, blk, idx, slot, o0, o1, o2;
    int i;

    mk = bpf_map_lookup_elem(&syn_marks, &key);

    if (mk == NULL) {
        return VG_SYN_UNREADY;
    }

    /*
     * The coarse clock with the atomic variant (5.12+, so it has the
     * helper, 5.11+): a read from memory, where bpf_ktime_get_ns() reads
     * the clocksource, about 13 us a call with HPET, as on a VM whose TSC
     * is unstable. A tick's resolution is ample for 0.9 s generations;
     * the userspace thread reads the same clock (syn_guard.c).
     */
    g = (atomic ? bpf_ktime_get_coarse_ns() : bpf_ktime_get_ns())
        / VG_SYN_GEN_NS;

    slot = syn_slot(g);

    if (mk->gen[slot] != g) {
        return VG_SYN_UNREADY;
    }

    blk = (__u32) h & ((1U << log2) - 1);
    h >>= log2;
    o0 = h & (VG_SYN_BLOCK_BITS - 1);
    o1 = (h >> VG_SYN_BLOCK_LOG2) & (VG_SYN_BLOCK_BITS - 1);
    o2 = (h >> (2 * VG_SYN_BLOCK_LOG2)) & (VG_SYN_BLOCK_BITS - 1);

#pragma unroll
    for (i = 1; i <= VG_SYN_OLDER; i++) {
        gi = g - i;
        idx = syn_slot(gi);

        /* stale: cleared for another generation, or never */
        if (mk->gen[idx] != gi) {
            continue;
        }

        idx = idx << log2 | blk;
        b = bpf_map_lookup_elem(&syn_bloom, &idx);

        if (b != NULL && syn_bit(b, o0) && syn_bit(b, o1)
            && syn_bit(b, o2))
        {
            return VG_SYN_RETRANS;
        }
    }

    idx = slot << log2 | blk;
    b = bpf_map_lookup_elem(&syn_bloom, &idx);

    if (b == NULL) {
        return VG_SYN_UNREADY;
    }

    syn_set(b, o0, atomic);
    syn_set(b, o1, atomic);
    syn_set(b, o2, atomic);

    return VG_SYN_DROP;
}


/* syn_filter() once for each variant, global: verified once, and the
 * plain one, all a kernel before 5.12 loads, has no atomic OR.
 */
__noinline int
vg_syn_filter(__u64 h)
{
    return syn_filter(h, 1);
}


__noinline int
vg_syn_filter_pl(__u64 h)
{
    return syn_filter(h, 0);
}


/* An engaged first-SYN drop's verdict on a SYN of key hash h: VG_DROP
 * for a first SYN; otherwise the SYN goes on through the checks after it,
 * the drop LPM's included (Seawall proposal 0023 §1).
 */
static __always_inline int
syn_judge(struct vg_metrics *m, __u64 pkts, __u64 h, int atomic)
{
    int rc = atomic ? vg_syn_filter(h) : vg_syn_filter_pl(h);

    if (rc == VG_SYN_DROP) {
        m->syn_guard_dropped += pkts;

        return VG_DROP;
    }

    if (rc == VG_SYN_RETRANS) {
        m->syn_guard_retrans += pkts;

    } else {
        m->syn_guard_unready += pkts;
    }

    return VG_PASS;
}


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
            if (_c == NULL) { \
                (m)->map_full++; \
            } \
        } \
        \
        _c; \
    })

static __always_inline void
host_count_in(struct host_counters *c, __u64 pkts, __u64 bytes)
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


/* Is this packet to a local address, parsed with status rc, a reply to a
 * flow the host opened: what sw_flowd's sf_is_reply() or, for an ICMP
 * error, sf_icmp_err_reply() says is one, within
 * reply_idle_ns, TCP's and UDP's alike (Seawall proposal 0015 §2 and §3)?
 * A path MTU error with no flow behind it is not: it costs nothing to
 * forge, and passing it would let a flood past the count and the drops.
 */
static __always_inline int
is_reply(const struct vg_cfg *c, int rc, const struct pkt_meta *pm,
    void *ctx, int hook)
{
    struct sf_idle idle;

    if (rc != PKT_OK) {
        return 0;
    }

    idle.tcp_ns = c->reply_idle_ns;
    idle.udp_ns = c->reply_idle_ns;

    if (sf_is_reply(&flows, &flows_config, pm, &idle) == SF_REPLY) {
        return 1;
    }

    if (!sf_is_icmp_err(pm)) {
        return 0;
    }

    if (hook == VG_HOOK_XDP) {
        return vg_icmp_err_xdp(ctx, &idle) == SF_REPLY;
    }

    return vg_icmp_err_tc(ctx, &idle) == SF_REPLY;
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
 * The ports and the ICMPv6 type are read on PKT_OK only, and are 0
 * otherwise, as libpkt leaves them: read whatever the status, clang
 * stored them again before each of the parse's early returns, which cost
 * IPv4 4-11 ns a frame.
 */
static __always_inline int
vg_judge(void *data, void *data_end, struct vg_cfg *c, struct vg_metrics *m,
    __u64 pkts, __u64 pkt_len, void *ctx, int hook, int atomic)
{
    struct pkt_meta pm;
    __u16 sport, dport;
    __u8 icmp6_type;
    __u64 ports_seq;
    int rc, local, reply, syn;

    syn = 0;
    rc = pkt_parse(data, data_end, &pm);

    if (rc == PKT_NOT_IP) {
        m->non_ip++;

        goto pass;
    }

    if (pm.family == 0) {
        m->parse_err++;

        return VG_PASS;
    }

    if (rc == PKT_OK) {
        sport = bpf_ntohs(pm.sport);
        dport = bpf_ntohs(pm.dport);
        /* read on the IPv6 path only, where libpkt reads ICMPv6 alone */
        icmp6_type = pm.icmp_type;

    } else {
        sport = 0;
        dport = 0;
        icmp6_type = 0;

        if (rc != PKT_NO_L4) {
            m->parse_err++;
        }
    }

    /* the key's ports and sequence number, as in the packet */
    ports_seq = (__u64) pm.sport << 48 | (__u64) pm.dport << 32
                | pm.tcp_seq;

    if (pm.family == PKT_V4) {
        __be32 saddr, daddr;

        __builtin_memcpy(&saddr, pm.addr_src, 4);
        __builtin_memcpy(&daddr, pm.addr_dst, 4);

        /* before the allow checks: a reply is counted whatever passes it */
        local = v4_in_lpm(&local_v4, daddr);
        reply = c->flows && local && is_reply(c, rc, &pm, ctx, hook);

        if (reply) {
            reply_count(m, pkts, pkt_len);
        }

        if (v4_in_lpm(&allow_v4, saddr) || v4_in_lpm(&allow_v4, daddr)) {
            goto v4_count;
        }

        /* a pure SYN: libpkt leaves tcp_flags 0 short of PKT_OK; never a
         * reply, which sw_flowd finds only with ACK or RST
         */
        syn = c->syn_guard && local
              && pm.l4_proto == IPPROTO_TCP
              && (pm.tcp_flags & (PKT_TCP_SYN | PKT_TCP_ACK)) == PKT_TCP_SYN;

        if (syn) {
            /* a blocked source never reaches the filter, nor counts to
             * engage it; to allow_ports, it goes through the filter first
             */
            if (!port_allowed(c, dport)
                && (v4_in_lpm(&drop_v4, saddr) || v4_in_lpm(&drop_v4, daddr)))
            {
                m->dropped += pkts;

                return VG_DROP;
            }

            m->syn_unproven += pkts;

            if (c->syn_engaged
                && syn_judge(m, pkts,
                             vg_syn_hash((__u64) saddr << 32 | daddr,
                                         ports_seq, 0, 0, 0),
                             atomic) == VG_DROP)
            {
                return VG_DROP;
            }
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

        /* not counted against its source, which it would get banned */
        if (reply) {
            host_count_in(VG_HASH_GET(host_v4, &daddr, m), pkts, pkt_len);

            m->reply_passed += pkts;

            goto pass;
        }

        if (v4_in_lpm(&drop_v4, saddr) || v4_in_lpm(&drop_v4, daddr)) {
            m->dropped += pkts;

            return VG_DROP;
        }


        v4_count:

        if (local) {
            host_count_in(VG_HASH_GET(host_v4, &daddr, m), pkts, pkt_len);

            /* a pure SYN isn't the source's to answer for (0023 §5) */
            if (!syn) {
                host_count_in(VG_HASH_GET(remote_v4, &saddr, m), pkts,
                              pkt_len);
            }
        }

        goto pass;
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

        /* before the exemptions: a reply is counted whatever passes it */
        local = v6_in_lpm(&local_v6, daddr.addr);
        reply = c->flows && local && is_reply(c, rc, &pm, ctx, hook);

        if (reply) {
            reply_count(m, pkts, pkt_len);
        }

        if (v6_is_linklocal(saddr.addr) || v6_is_linklocal(daddr.addr)
            || v6_is_mcast_link(saddr.addr) || v6_is_mcast_link(daddr.addr))
        {
            goto v6_count;
        }

        /* RFC 4861: real NDP is sent with hop limit 255 and the kernel drops
         * anything else, so a routed NS/RA flood cannot use this exemption.
         */
        if (pm.l4_proto == IPPROTO_ICMPV6
            && icmp6_type >= VG_NDISC_RS && icmp6_type <= VG_NDISC_REDIRECT
            && v6_hop_limit(data, data_end, pm.l3_off) == VG_NDISC_HOP_LIMIT)
        {
            goto v6_count;
        }

        if (v6_in_lpm(&allow_v6, saddr.addr)
            || v6_in_lpm(&allow_v6, daddr.addr))
        {
            goto v6_count;
        }

        syn = c->syn_guard && local
              && pm.l4_proto == IPPROTO_TCP
              && (pm.tcp_flags & (PKT_TCP_SYN | PKT_TCP_ACK)) == PKT_TCP_SYN;

        if (syn) {
            __u64 a[4];

            if (!port_allowed(c, dport)
                && (v6_in_lpm(&drop_v6, saddr.addr)
                    || v6_in_lpm(&drop_v6, daddr.addr)))
            {
                m->dropped += pkts;

                return VG_DROP;
            }

            m->syn_unproven += pkts;

            if (c->syn_engaged) {
                __builtin_memcpy(a, saddr.addr, 16);
                __builtin_memcpy(&a[2], daddr.addr, 16);

                if (syn_judge(m, pkts,
                              vg_syn_hash(a[0], a[1], a[2], a[3], ports_seq),
                              atomic) == VG_DROP)
                {
                    return VG_DROP;
                }
            }
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

        if (reply) {
            host_count_in(VG_HASH_GET(host_v6, &daddr, m), pkts, pkt_len);

            m->reply_passed += pkts;

            goto pass;
        }

        if (v6_in_lpm(&drop_v6, saddr.addr)
            || v6_in_lpm(&drop_v6, daddr.addr))
        {
            m->dropped += pkts;

            return VG_DROP;
        }


        v6_count:

        if (local) {
            host_count_in(VG_HASH_GET(host_v6, &daddr, m), pkts, pkt_len);

            if (!syn) {
                host_count_in(VG_HASH_GET(remote_v6, &saddr, m), pkts,
                              pkt_len);
            }
        }

        goto pass;
    }

    pass:

    m->passed += pkts;

    return VG_PASS;
}


static __always_inline void
rx_count(struct vg_metrics *m, __u64 pkts, __u64 bytes)
{
    m->rx_pkts += pkts;
    m->rx_bytes += bytes;
}


static __always_inline void
reply_count(struct vg_metrics *m, __u64 pkts, __u64 bytes)
{
    m->rx_reply_pkts += pkts;
    m->rx_reply_bytes += bytes;
}


/* An idle gate judges nothing, but counts the replies to the host's own
 * flows among what it passes, as an armed one does in vg_judge(), so they
 * don't wake it (Seawall proposal 0017 §1). Only a fully parsed frame
 * can be one, as is_reply() says.
 */
static __always_inline void
idle_replies(void *data, void *data_end, const struct vg_cfg *c,
    struct vg_metrics *m, __u64 pkts, __u64 pkt_len, void *ctx, int hook)
{
    struct pkt_meta pm;
    int rc;

    rc = pkt_parse(data, data_end, &pm);

    if (rc != PKT_OK) {
        return;
    }

    if (pm.family == PKT_V4) {
        __be32 daddr;

        __builtin_memcpy(&daddr, pm.addr_dst, 4);

        if (!v4_in_lpm(&local_v4, daddr)) {
            return;
        }

    } else {
        struct vg_ip6 daddr;

        __builtin_memcpy(daddr.addr, pm.addr_dst, 16);

        if (!v6_in_lpm(&local_v6, daddr.addr)) {
            return;
        }
    }

    if (is_reply(c, rc, &pm, ctx, hook)) {
        reply_count(m, pkts, pkt_len);
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

struct {
    __uint(priority, 10);
    __uint(XDP_PASS, 1);
} XDP_RUN_CONFIG(voidgate_xdp_pl);

static __always_inline int
xdp_entry(struct xdp_md *ctx, int atomic)
{
    void *data = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;
    struct vg_metrics *m = get_metrics();
    struct vg_cfg *c;
    __u64 pkt_len = bpf_xdp_get_buff_len(ctx);

    /* never NULL, key 0 of a one-entry array: checked once here for
     * the verifier, which knows it from then on, inlined calls included
     */
    if (m == NULL) {
        return XDP_PASS;
    }

    rx_count(m, 1, pkt_len);

    c = get_cfg();

    if (c == NULL) {
        m->passed++;

        return XDP_PASS;
    }

    if (c->armed == 0) {
        if (c->flows) {
            idle_replies(data, data_end, c, m, 1, pkt_len, ctx, VG_HOOK_XDP);
        }

        m->passed++;

        return XDP_PASS;
    }

    if (vg_judge(data, data_end, c, m, 1, pkt_len, ctx, VG_HOOK_XDP, atomic)
        == VG_DROP)
    {
        return XDP_DROP;
    }

    return XDP_PASS;
}


SEC("xdp.frags")
int
voidgate_xdp(struct xdp_md *ctx)
{
    return xdp_entry(ctx, 1);
}


/* before 5.12: no atomic OR */
SEC("xdp.frags")
int
voidgate_xdp_pl(struct xdp_md *ctx)
{
    return xdp_entry(ctx, 0);
}


/* Pass is TC_ACT_UNSPEC, which is tcx's TCX_NEXT: classic TC and tcx both
 * go on to the next program, mini-fw's. A GRO'd skb counts as its
 * segments, as XDP saw them.
 */
static __always_inline int
tc_entry(struct __sk_buff *ctx, int atomic)
{
    struct vg_metrics *m = get_metrics();
    struct vg_cfg *c;
    void *data, *data_end;
    __u64 pkts = ctx->gso_segs ? ctx->gso_segs : 1;
    __u32 want;

    /* never NULL, key 0 of a one-entry array: checked once here for
     * the verifier, which knows it from then on, inlined calls included
     */
    if (m == NULL) {
        return TC_ACT_UNSPEC;
    }

    rx_count(m, pkts, ctx->len);

    c = get_cfg();

    if (c == NULL || (c->armed == 0 && !c->flows)) {
        m->passed += pkts;

        return TC_ACT_UNSPEC;
    }

    /* A TC program reads only the skb's linear part, which may hold just
     * the Ethernet header. Pull only when it is short of PKT_ICMP_ERR_MAX,
     * the most libpkt reads, an ICMP error's embedded header included: a
     * pull makes the skb writable, copying a cloned skb's head. One that
     * fails leaves the short view, judged without ports, like a truncated
     * header.
     */
    data = (void *) (long) ctx->data;
    data_end = (void *) (long) ctx->data_end;
    want = ctx->len < PKT_ICMP_ERR_MAX ? ctx->len : PKT_ICMP_ERR_MAX;

    if (data + want > data_end) {
        bpf_skb_pull_data(ctx, want);
        data = (void *) (long) ctx->data;
        data_end = (void *) (long) ctx->data_end;
    }

    if (c->armed == 0) {
        idle_replies(data, data_end, c, m, pkts, ctx->len, ctx, VG_HOOK_TC);
        m->passed += pkts;

        return TC_ACT_UNSPEC;
    }

    if (vg_judge(data, data_end, c, m, pkts, ctx->len, ctx, VG_HOOK_TC,
                 atomic) == VG_DROP)
    {
        return TC_ACT_SHOT;
    }

    return TC_ACT_UNSPEC;
}


SEC("tc")
int
voidgate_tc(struct __sk_buff *ctx)
{
    return tc_entry(ctx, 1);
}


/* before 5.12: no atomic OR */
SEC("tc")
int
voidgate_tc_pl(struct __sk_buff *ctx)
{
    return tc_entry(ctx, 0);
}


char LICENSE[] SEC("license") = "GPL";
