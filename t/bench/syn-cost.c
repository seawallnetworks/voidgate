/*
 * syn-cost: what first-SYN drop costs a frame, and how many spoofed SYNs
 * its filter passes as retransmissions (Seawall proposal 0023 Plan 5).
 *
 * By BPF_PROG_TEST_RUN: the XDP program alone, its maps its own. Two
 * parts:
 *
 * 1. ns a frame, one frame run 200,000 times, its cache warm: an armed
 *    gate's non-SYN, a SYN in standby, a first SYN (dropped; its bits set
 *    already after the first run), a retransmission found in the oldest
 *    generation checked (all 4 read), a SYN with no slot ready.
 *
 * 2. under a flood of R spoofed SYNs a second: the 4 older generations
 *    filled from here, through mmap, with the 0.9 R keys a generation
 *    holds (random hashes, as random keys give; the hash's C copy
 *    matches the program's, which syn-bits checks); then fresh random
 *    SYNs through the program, each once: the share that pass as
 *    retransmissions, against the model's estimate (the one status
 *    reports, syn_guard_fp_est), and ns a frame, cold: each a different
 *    key in a filter of 6 x 2^bits bits, next to the same SYNs with the
 *    filter in standby. Timed by BPF's run-time statistics, which add
 *    their own few tens of ns to every figure.
 *
 *   make t/bench/syn-cost && sudo t/bench/syn-cost [-p] [-b bits]
 *
 * -p: the entry without atomic OR, for a kernel before 5.12. -b: bits a
 * generation, as syn_guard_bits (25).
 */

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "voidgate.h"
#include "voidgate.skel.h"


#define REPEAT     200000
#define ROUNDS     5
#define PROBES     200000
#define BATCH      2000
#define FRAME_LEN  (sizeof(struct ethhdr) + sizeof(struct iphdr)        \
                    + sizeof(struct tcphdr))
#define LOCAL      "198.51.100.10"


typedef struct {
    struct voidgate_bpf  *s;
    int                   prog;
    uint32_t              log2;
    size_t                blocks;
    struct vg_syn_block  *bloom;
    struct vg_syn_marks  *marks;
    uint64_t              k0, k1;
} bench_t;


static uint64_t  rng = 0x9e3779b97f4a7c15ULL;


#define ROTL(x, b)  (((x) << (b)) | ((x) >> (64 - (b))))
#define ROUND(v0, v1, v2, v3)                                               \
    do {                                                                    \
        v0 += v1; v1 = ROTL(v1, 13); v1 ^= v0; v0 = ROTL(v0, 32);           \
        v2 += v3; v3 = ROTL(v3, 16); v3 ^= v2;                              \
        v0 += v3; v3 = ROTL(v3, 21); v3 ^= v0;                              \
        v2 += v1; v1 = ROTL(v1, 17); v1 ^= v2; v2 = ROTL(v2, 32);           \
    } while (0)


/* splitmix64 */
static uint64_t
rand64(void)
{
    uint64_t z = (rng += 0x9e3779b97f4a7c15ULL);

    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;

    return z ^ (z >> 31);
}


/* SipHash-1-3 of five words, as vg_syn_hash() in voidgate.bpf.c */
static uint64_t
sip13(const bench_t *b, const uint64_t m[5])
{
    uint64_t v0 = b->k0 ^ 0x736f6d6570736575ULL;
    uint64_t v1 = b->k1 ^ 0x646f72616e646f6dULL;
    uint64_t v2 = b->k0 ^ 0x6c7967656e657261ULL;
    uint64_t v3 = b->k1 ^ 0x7465646279746573ULL;
    uint64_t f = 40ULL << 56;
    int i;

    for (i = 0; i < 5; i++) {
        v3 ^= m[i];
        ROUND(v0, v1, v2, v3);
        v0 ^= m[i];
    }

    v3 ^= f;
    ROUND(v0, v1, v2, v3);
    v0 ^= f;
    v2 ^= 0xff;
    ROUND(v0, v1, v2, v3);
    ROUND(v0, v1, v2, v3);
    ROUND(v0, v1, v2, v3);

    return v0 ^ v1 ^ v2 ^ v3;
}


/* h's three bits set in slot's block, as syn_filter() sets them */
static void
set_bits(bench_t *b, uint32_t slot, uint64_t h)
{
    struct vg_syn_block *blk;
    uint32_t o;
    int k;

    blk = &b->bloom[(size_t) slot * b->blocks + (h & (b->blocks - 1))];
    h >>= b->log2;

    for (k = 0; k < 3; k++) {
        o = (h >> (k * VG_SYN_BLOCK_LOG2)) & (VG_SYN_BLOCK_BITS - 1);
        blk->w[o >> 6] |= 1ULL << (o & 63);
    }
}


/* a frame to LOCAL:80 from saddr:sport with seq and flags */
static void
frame(unsigned char *buf, uint32_t saddr, uint16_t sport, uint32_t seq,
    int syn, int ack)
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
    ip->saddr = saddr;
    inet_pton(AF_INET, LOCAL, &ip->daddr);
    tcp->source = sport;
    tcp->dest = htons(80);
    tcp->seq = seq;
    tcp->doff = 5;
    tcp->syn = syn;
    tcp->ack = ack;
}


/* the frame's key's hash, as vg_judge() makes it */
static uint64_t
frame_hash(const bench_t *b, const unsigned char *buf)
{
    const struct iphdr   *ip = (const struct iphdr *) (buf
                                                       + sizeof(struct ethhdr));
    const struct tcphdr  *tcp = (const struct tcphdr *) (ip + 1);
    uint64_t              m[5] = { 0 };

    m[0] = (uint64_t) ip->saddr << 32 | ip->daddr;
    m[1] = (uint64_t) tcp->source << 48 | (uint64_t) tcp->dest << 32
           | tcp->seq;

    return sip13(b, m);
}


/* the clock the loaded program reads: coarse, but plain's precise one */
static clockid_t  gen_clock = CLOCK_MONOTONIC_COARSE;


static uint64_t
gen_now(void)
{
    struct timespec ts;

    clock_gettime(gen_clock, &ts);

    return ((uint64_t) ts.tv_sec * 1000000000ULL + ts.tv_nsec)
           / VG_SYN_GEN_NS;
}


static void
set_cfg(bench_t *b, uint32_t engaged)
{
    struct vg_cfg  c = { .armed = 1, .syn_guard = 1 };
    uint32_t       key = 0;

    c.syn_engaged = engaged;
    bpf_map_update_elem(bpf_map__fd(b->s->maps.cfg), &key, &c, 0);
}


/*
 * Generation g and the 4 before it marked for their slots, the others
 * for none; the current slot zeroed. With older, the 4 older slots get
 * those images, else they are zeroed too.
 */
static uint64_t
set_gens(bench_t *b, struct vg_syn_block **older)
{
    uint64_t g = gen_now(), gi;
    size_t   len = b->blocks * sizeof(struct vg_syn_block);
    int      i;

    for (i = 0; i < VG_SYN_SLOTS; i++) {
        __atomic_store_n(&b->marks->gen[i], VG_SYN_MARK_NONE,
                         __ATOMIC_RELAXED);
    }

    for (i = 0; i <= VG_SYN_OLDER; i++) {
        gi = g - (uint64_t) i;

        if (i == 0 || older == NULL) {
            memset(&b->bloom[(gi % VG_SYN_SLOTS) * b->blocks], 0, len);

        } else {
            memcpy(&b->bloom[(gi % VG_SYN_SLOTS) * b->blocks], older[i - 1],
                   len);
        }

        __atomic_store_n(&b->marks->gen[gi % VG_SYN_SLOTS], gi,
                         __ATOMIC_RELEASE);
    }

    return g;
}


typedef void (*prep_pt)(bench_t *b, unsigned char *buf);


/*
 * One frame run *repeat times, best of ROUNDS: ns, and its verdict. Each
 * round from prep's state, and counted only if no generation turned
 * during it: the runs after one would find another state. One that did
 * halves *repeat, so a slow frame's rounds fit in a generation: with the
 * plain entry, bpf_ktime_get_ns() alone may take 13 us (HPET).
 */
static double
warm(bench_t *b, unsigned char *buf, prep_pt prep, uint32_t *verdict,
    uint32_t *repeat)
{
    double    best = 0;
    int       i = 0;
    uint64_t  g;

    while (i < ROUNDS) {
        LIBBPF_OPTS(bpf_test_run_opts, o, .data_in = buf,
                    .data_size_in = FRAME_LEN, .repeat = *repeat);

        g = gen_now();
        prep(b, buf);

        if (bpf_prog_test_run_opts(b->prog, &o) != 0) {
            fprintf(stderr, "test run: %s\n", strerror(errno));
            exit(1);
        }

        if (gen_now() != g) {
            if (*repeat > 1000) {
                *repeat /= 2;
            }

            continue;
        }

        *verdict = o.retval;

        if (i++ == 0 || o.duration < best) {
            best = o.duration;
        }
    }

    return best;
}


/*
 * The program's run time and runs so far, by BPF's run-time statistics
 * (on while main() holds bpf_enable_stats()'s fd): sched_clock() around
 * each run, which a VM reads from the TSC, where bpf_ktime_get_ns(),
 * around a test run's batch, may cost microseconds itself (HPET).
 */
static void
run_stats(bench_t *b, uint64_t *ns, uint64_t *cnt)
{
    struct bpf_prog_info  pi;
    __u32                 len = sizeof(pi);

    memset(&pi, 0, sizeof(pi));

    if (bpf_prog_get_info_by_fd(b->prog, &pi, &len) != 0) {
        fprintf(stderr, "prog info: %s\n", strerror(errno));
        exit(1);
    }

    *ns = pi.run_time_ns;
    *cnt = pi.run_cnt;
}


/* the counter at off in struct vg_metrics, summed over CPUs */
static uint64_t
metric(bench_t *b, size_t off)
{
    int                 i, n = libbpf_num_possible_cpus();
    uint32_t            key = 0;
    uint64_t            sum = 0;
    struct vg_metrics  *m = calloc(n, sizeof(*m));

    if (m == NULL
        || bpf_map_lookup_elem(bpf_map__fd(b->s->maps.metrics), &key, m)
           != 0)
    {
        fprintf(stderr, "metrics: %s\n", strerror(errno));
        exit(1);
    }

    for (i = 0; i < n; i++) {
        sum += *(uint64_t *) ((char *) &m[i] + off);
    }

    free(m);

    return sum;
}


/* the share of never-seen keys passing, as policy.c's syn_fp_est() */
static double
model(double per_gen, size_t blocks)
{
    double lambda = per_gen / (double) blocks, lo, hi, j, p = 0;

    lo = floor(lambda - 12 * sqrt(lambda) - 30);
    hi = ceil(lambda + 12 * sqrt(lambda) + 30);

    for (j = lo > 0 ? lo : 0; j <= hi; j++) {
        p += exp(j * log(lambda) - lambda - lgamma(j + 1))
             * pow(1 - pow(1 - 1.0 / VG_SYN_BLOCK_BITS, 3 * j), 3);
    }

    return 1 - pow(1 - p, VG_SYN_OLDER);
}


/* the states part_warm()'s frames run from */
static void
prep_ack(bench_t *b, unsigned char *buf)
{
    set_cfg(b, 1);
    set_gens(b, NULL);
    frame(buf, htonl(0xcb007101), htons(40000), htonl(1), 0, 1);
}


static void
prep_standby(bench_t *b, unsigned char *buf)
{
    set_cfg(b, 0);
    set_gens(b, NULL);
    frame(buf, htonl(0xcb007101), htons(40001), htonl(2), 1, 0);
}


/* its bits set by the first run, read by the rest: a duplicate */
static void
prep_first(bench_t *b, unsigned char *buf)
{
    set_cfg(b, 1);
    set_gens(b, NULL);
    frame(buf, htonl(0xcb007101), htons(40002), htonl(3), 1, 0);
}


/* in the 4th older generation: all 4 read */
static void
prep_retrans(bench_t *b, unsigned char *buf)
{
    uint64_t g;

    set_cfg(b, 1);
    g = set_gens(b, NULL);
    frame(buf, htonl(0xcb007101), htons(40003), htonl(4), 1, 0);
    set_bits(b, (uint32_t) ((g - VG_SYN_OLDER) % VG_SYN_SLOTS),
             frame_hash(b, buf));
}


static void
prep_unready(bench_t *b, unsigned char *buf)
{
    int i;

    set_cfg(b, 1);
    set_gens(b, NULL);

    for (i = 0; i < VG_SYN_SLOTS; i++) {
        b->marks->gen[i] = VG_SYN_MARK_NONE;
    }

    frame(buf, htonl(0xcb007101), htons(40004), htonl(5), 1, 0);
}


static void
part_warm(bench_t *b)
{
    static const struct {
        const char  *name;
        prep_pt      prep;
    } cases[] = {
        { "armed, an ACK, engaged", prep_ack },
        { "a SYN, standby", prep_standby },
        { "a SYN, no slot ready", prep_unready },
        { "a retransmission, 4th older", prep_retrans },
        { "a first SYN, engaged", prep_first },
    };

    unsigned char  buf[FRAME_LEN];
    uint32_t       v, repeat;
    double         ns;
    size_t         i;

    printf("ns a frame, warm, best of %d runs of %d, or of fewer that fit "
           "in a generation\n", ROUNDS, REPEAT);

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        repeat = REPEAT;
        ns = warm(b, buf, cases[i].prep, &v, &repeat);
        printf("  %-30s %6.1f  %s", cases[i].name, ns,
               v == XDP_PASS ? "pass" : "DROP");

        if (repeat != REPEAT) {
            printf("  (runs of %u)", repeat);
        }

        printf("\n");
    }
}


/*
 * Fresh SYNs, each once, first-SYN drop in standby: what the rest of the
 * program costs them cold, the filter's share being the difference.
 */
static void
part_cold_standby(bench_t *b)
{
    unsigned char  buf[FRAME_LEN];
    uint64_t       t0, t1, c0, c1;
    int            j;

    set_cfg(b, 0);
    run_stats(b, &t0, &c0);

    for (j = 0; j < PROBES; j++) {
        LIBBPF_OPTS(bpf_test_run_opts, o, .data_in = buf,
                    .data_size_in = FRAME_LEN, .repeat = 1);

        frame(buf, (uint32_t) rand64(), (uint16_t) rand64(),
              (uint32_t) rand64(), 1, 0);

        if (bpf_prog_test_run_opts(b->prog, &o) != 0) {
            fprintf(stderr, "test run: %s\n", strerror(errno));
            exit(1);
        }
    }

    run_stats(b, &t1, &c1);
    printf("  %9s  %9s  %9s  %6.1f  (standby: no filter)\n", "-", "-", "-",
           (double) (t1 - t0) / (double) (c1 - c0));
}


/*
 * rate spoofed SYNs a second: the 4 older generations hold 0.9 rate
 * random keys each; PROBES fresh ones run once each, in batches that a
 * generation's turn doesn't split (one that is split is run again on the
 * generations set anew).
 */
static void
part_flood(bench_t *b, double rate)
{
    struct vg_syn_block  *older[VG_SYN_OLDER];
    unsigned char         buf[FRAME_LEN];
    size_t                len = b->blocks * sizeof(struct vg_syn_block);
    uint64_t              n, i, g, r0, r1, passed = 0, runs = 0, ns = 0;
    uint64_t              t0, t1, c0, c1, bpassed;
    int                   k, j;
    size_t                off = offsetof(struct vg_metrics,
                                         syn_guard_retrans);

    n = (uint64_t) (rate * VG_SYN_GEN_NS / 1e9);

    for (k = 0; k < VG_SYN_OLDER; k++) {
        older[k] = calloc(1, len);

        if (older[k] == NULL) {
            fprintf(stderr, "out of memory\n");
            exit(1);
        }

        /* in slot 0 of b's layout, then copied: set_bits() takes a slot */
        for (i = 0; i < n; i++) {
            uint64_t             h = rand64();
            struct vg_syn_block *blk = &older[k][h & (b->blocks - 1)];
            uint32_t             o;
            int                  t;

            h >>= b->log2;

            for (t = 0; t < 3; t++) {
                o = (h >> (t * VG_SYN_BLOCK_LOG2)) & (VG_SYN_BLOCK_BITS - 1);
                blk->w[o >> 6] |= 1ULL << (o & 63);
            }
        }
    }

    set_cfg(b, 1);
    g = set_gens(b, older);

    while (runs < PROBES) {
        r0 = metric(b, off);
        run_stats(b, &t0, &c0);

        for (j = 0; j < BATCH; j++) {
            LIBBPF_OPTS(bpf_test_run_opts, o, .data_in = buf,
                        .data_size_in = FRAME_LEN, .repeat = 1);

            frame(buf, (uint32_t) rand64(), (uint16_t) rand64(),
                  (uint32_t) rand64(), 1, 0);

            if (bpf_prog_test_run_opts(b->prog, &o) != 0) {
                fprintf(stderr, "test run: %s\n", strerror(errno));
                exit(1);
            }
        }

        run_stats(b, &t1, &c1);
        r1 = metric(b, off);
        bpassed = r1 - r0;

        if (c1 - c0 != BATCH) {
            fprintf(stderr, "run_cnt %llu, not %d: stats off?\n",
                    (unsigned long long) (c1 - c0), BATCH);
            exit(1);
        }

        if (gen_now() != g) {
            g = set_gens(b, older);
            continue;
        }

        passed += bpassed;
        ns += t1 - t0;
        runs += BATCH;
    }

    printf("  %9.0f  %8.4f%%  %8.4f%%  %6.1f\n", rate,
           100.0 * passed / runs, 100.0 * model(n, b->blocks),
           (double) ns / runs);

    for (k = 0; k < VG_SYN_OLDER; k++) {
        free(older[k]);
    }
}


int
main(int argc, char **argv)
{
    static const double  rates[] = { 100000, 1000000, 3000000, 10000000 };
    struct vg_lpm_v4     lk = { .prefixlen = 32 };
    bench_t              b;
    uint8_t              one = 1;
    int                  i, bits = 25, plain = 0, stats_fd;
    size_t               k;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0) {
            plain = 1;
            gen_clock = CLOCK_MONOTONIC;

        } else if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            bits = atoi(argv[++i]);

        } else {
            fprintf(stderr, "usage: syn-cost [-p] [-b bits]\n");
            return 1;
        }
    }

    if (bits < VG_SYN_BITS_MIN || bits > VG_SYN_BITS_MAX) {
        fprintf(stderr, "bits: %d to %d\n", VG_SYN_BITS_MIN,
                VG_SYN_BITS_MAX);
        return 1;
    }

    setvbuf(stdout, NULL, _IOLBF, 0);
    memset(&b, 0, sizeof(b));
    b.log2 = (uint32_t) bits - VG_SYN_BLOCK_LOG2;
    b.blocks = (size_t) 1 << b.log2;
    b.k0 = rand64();
    b.k1 = rand64();

    b.s = voidgate_bpf__open();

    if (b.s == NULL) {
        fprintf(stderr, "open: %s\n", strerror(errno));
        return 1;
    }

    bpf_map__set_max_entries(b.s->maps.syn_bloom, VG_SYN_SLOTS << b.log2);
    b.s->rodata->vg_syn_blocks_log2 = b.log2;
    b.s->rodata->vg_syn_k0 = b.k0;
    b.s->rodata->vg_syn_k1 = b.k1;

    bpf_program__set_autoload(b.s->progs.voidgate_xdp, !plain);
    bpf_program__set_autoload(b.s->progs.voidgate_xdp_pl, plain);
    bpf_program__set_autoload(b.s->progs.voidgate_tc, false);
    bpf_program__set_autoload(b.s->progs.voidgate_tc_pl, false);

    if (voidgate_bpf__load(b.s) != 0) {
        fprintf(stderr, "load: %s\n", strerror(errno));
        return 1;
    }

    b.prog = bpf_program__fd(plain ? b.s->progs.voidgate_xdp_pl
                                   : b.s->progs.voidgate_xdp);
    inet_pton(AF_INET, LOCAL, lk.data);
    bpf_map_update_elem(bpf_map__fd(b.s->maps.local_v4), &lk, &one, 0);

    b.bloom = mmap(NULL, VG_SYN_SLOTS * b.blocks * sizeof(*b.bloom),
                   PROT_READ | PROT_WRITE, MAP_SHARED,
                   bpf_map__fd(b.s->maps.syn_bloom), 0);
    b.marks = mmap(NULL, sizeof(*b.marks), PROT_READ | PROT_WRITE,
                   MAP_SHARED, bpf_map__fd(b.s->maps.syn_marks), 0);

    if (b.bloom == MAP_FAILED || b.marks == MAP_FAILED) {
        fprintf(stderr, "mmap: %s\n", strerror(errno));
        return 1;
    }

    stats_fd = bpf_enable_stats(BPF_STATS_RUN_TIME);

    if (stats_fd < 0) {
        fprintf(stderr, "bpf_enable_stats: %s\n", strerror(errno));
        return 1;
    }

    printf("syn-cost: %s, 2^%d bits a generation, %zu MB in all\n",
           plain ? "plain writes" : "atomic OR", bits,
           VG_SYN_SLOTS * b.blocks * sizeof(*b.bloom) >> 20);

    part_warm(&b);

    printf("spoofed SYNs a second: passed as retransmissions, measured "
           "and modelled, of %d fresh ones; ns a frame, cold\n", PROBES);
    printf("  %9s  %9s  %9s  %6s\n", "rate", "measured", "model", "ns");
    part_cold_standby(&b);

    for (k = 0; k < sizeof(rates) / sizeof(rates[0]); k++) {
        part_flood(&b, rates[k]);
    }

    close(stats_fd);
    voidgate_bpf__destroy(b.s);

    return 0;
}
