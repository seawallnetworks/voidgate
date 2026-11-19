/*
 * idle-cost: what voidgate's XDP program costs a frame, idle and armed,
 * with and without sw_flowd's table (Seawall proposal 0017 §1), by
 * BPF_PROG_TEST_RUN: the program alone, one frame run a million times
 * with a warm cache, its maps voidgate's own (nothing pinned, nothing
 * attached, gone at exit). The frame is a full-size TCP ACK to a local
 * address, from the peer of a flow in the table (a reply) or of none.
 *
 *   make t/bench/idle-cost && sudo t/bench/idle-cost
 */

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "voidgate.h"
#include "voidgate.skel.h"
#include <sw_flowd/sw_flowd.h>


#define REPEAT     1000000
#define ROUNDS     5
#define FRAME_LEN  1514
#define LOCAL      "198.51.100.10"
#define PEER       "198.51.100.1"
#define PEER_PORT  8080
#define LOCAL_PORT 40000


static void
frame(unsigned char *buf, uint16_t sport)
{
    struct ethhdr  *eth = (struct ethhdr *) buf;
    struct iphdr   *ip = (struct iphdr *) (eth + 1);
    struct tcphdr  *tcp = (struct tcphdr *) (ip + 1);

    memset(buf, 0, FRAME_LEN);
    eth->h_proto = htons(ETH_P_IP);
    ip->version = 4;
    ip->ihl = 5;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->tot_len = htons(FRAME_LEN - sizeof(*eth));
    inet_pton(AF_INET, PEER, &ip->saddr);
    inet_pton(AF_INET, LOCAL, &ip->daddr);
    tcp->source = htons(sport);
    tcp->dest = htons(LOCAL_PORT);
    tcp->doff = 5;
    tcp->ack = 1;
}


static double
run(int prog, unsigned char *buf)
{
    double  best = 0;
    int     i;

    for (i = 0; i < ROUNDS; i++) {
        LIBBPF_OPTS(bpf_test_run_opts, o,
                    .data_in = buf, .data_size_in = FRAME_LEN,
                    .repeat = REPEAT);

        if (bpf_prog_test_run_opts(prog, &o) != 0) {
            fprintf(stderr, "test run: %s\n", strerror(errno));
            exit(1);
        }

        if (o.retval != XDP_PASS) {
            fprintf(stderr, "expected XDP_PASS, got %u\n", o.retval);
            exit(1);
        }

        if (i == 0 || o.duration < best) {
            best = o.duration;
        }
    }

    return best;
}


/* rx_reply_pkts, summed over CPUs */
static unsigned long long
replies(struct voidgate_bpf *s)
{
    int                 i, n = libbpf_num_possible_cpus();
    uint32_t            key = 0;
    unsigned long long  sum = 0;
    struct vg_metrics  *m = calloc(n, sizeof(*m));

    if (m == NULL
        || bpf_map_lookup_elem(bpf_map__fd(s->maps.metrics), &key, m) != 0)
    {
        fprintf(stderr, "metrics: %s\n", strerror(errno));
        exit(1);
    }

    for (i = 0; i < n; i++) {
        sum += m[i].rx_reply_pkts;
    }

    free(m);

    return sum;
}


/* one case: its cost, and whether its frames counted as replies */
static void
bench(struct voidgate_bpf *s, int prog, const char *name,
    unsigned char *buf, int want_replies)
{
    unsigned long long  before = replies(s);
    double              ns = run(prog, buf);
    unsigned long long  got = replies(s) - before;

    if ((got > 0) != want_replies) {
        fprintf(stderr, "%s: %llu frames counted as replies\n", name, got);
        exit(1);
    }

    printf("  %-28s %6.1f\n", name, ns);
}


static void
set_cfg(struct voidgate_bpf *s, uint32_t armed, uint32_t flows)
{
    uint32_t       key = 0;
    struct vg_cfg  c;

    memset(&c, 0, sizeof(c));
    c.armed = armed;
    c.flows = flows;
    c.reply_idle_ns = 120ULL * 1000000000ULL;

    if (bpf_map_update_elem(bpf_map__fd(s->maps.cfg), &key, &c, 0) != 0) {
        fprintf(stderr, "cfg: %s\n", strerror(errno));
        exit(1);
    }
}


int
main(void)
{
    struct voidgate_bpf  *s;
    struct vg_lpm_v4      lk = { .prefixlen = 32 };
    struct sf_flow_key    fk;
    struct sf_flow        fv;
    struct timespec       ts;
    unsigned char         reply[FRAME_LEN], other[FRAME_LEN];
    uint8_t               one = 1;
    int                   prog;

    s = voidgate_bpf__open();
    if (s == NULL) {
        fprintf(stderr, "open: %s\n", strerror(errno));
        return 1;
    }

    /* the table's size as sw_flowd's default, not voidgate's placeholder */
    bpf_map__set_max_entries(s->maps.flows, 262144);
    bpf_program__set_autoload(s->progs.voidgate_tc, false);
    bpf_program__set_autoload(s->progs.voidgate_xdp_pl, false);
    bpf_program__set_autoload(s->progs.voidgate_tc_pl, false);

    if (voidgate_bpf__load(s) != 0) {
        fprintf(stderr, "load: %s\n", strerror(errno));
        return 1;
    }

    prog = bpf_program__fd(s->progs.voidgate_xdp);

    inet_pton(AF_INET, LOCAL, lk.data);
    bpf_map_update_elem(bpf_map__fd(s->maps.local_v4), &lk, &one, 0);

    memset(&fk, 0, sizeof(fk));
    fk.family = SF_FAMILY_V4;
    fk.protocol = SF_IPPROTO_TCP;
    inet_pton(AF_INET, PEER, fk.raddr);
    fk.rport = htons(PEER_PORT);
    fk.lport = htons(LOCAL_PORT);
    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
    fv.last_seen = ((uint64_t) ts.tv_sec * 1000000000ULL + ts.tv_nsec)
                   & ~SF_STATE_MASK;
    bpf_map_update_elem(bpf_map__fd(s->maps.flows), &fk, &fv, 0);

    frame(reply, PEER_PORT);
    frame(other, PEER_PORT + 1);

    printf("ns a frame, best of %d runs of %d\n", ROUNDS, REPEAT);
    set_cfg(s, 0, 0);
    bench(s, prog, "idle, no table (as before)", reply, 0);
    set_cfg(s, 0, 1);
    bench(s, prog, "idle, table, a reply", reply, 1);
    bench(s, prog, "idle, table, no reply", other, 0);
    set_cfg(s, 1, 1);
    bench(s, prog, "armed, table, a reply", reply, 1);
    bench(s, prog, "armed, table, no reply", other, 0);

    voidgate_bpf__destroy(s);

    return 0;
}
