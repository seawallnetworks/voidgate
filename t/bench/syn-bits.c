/*
 * syn-bits: no bit of first-SYN drop's Bloom filter is lost when several
 * CPUs write one cache line at once (Seawall proposal 0023 §2).
 *
 * The filter is cut to one block a slot, so every SYN writes the same
 * 64 bytes. Each round, a thread pinned to each CPU sends its own SYNs
 * through the XDP program (BPF_PROG_TEST_RUN) at the same moment; then the
 * block must hold every bit of every SYN sent, as the hash, computed here
 * too, places them. The entry with atomic OR must lose none; the plain one
 * (-p), for a kernel before 5.12, may, which shows the race is real.
 *
 *   make t/bench/syn-bits && sudo t/bench/syn-bits [-p] [rounds]
 */

#define _GNU_SOURCE         /* pthread_setaffinity_np(), CPU_SET() */

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <pthread.h>
#include <sched.h>
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


#define SYNS       8        /* a thread's SYNs a round */
#define MAX_CPUS   64
#define FRAME_LEN  (sizeof(struct ethhdr) + sizeof(struct iphdr)        \
                    + sizeof(struct tcphdr))
#define LOCAL      "198.51.100.10"
#define K0         0x0706050403020100ULL
#define K1         0x0f0e0d0c0b0a0908ULL


typedef struct {
    int                 cpu;
    int                 prog;
    unsigned char       frames[SYNS][FRAME_LEN];
} worker_t;


static pthread_barrier_t  start, done;
static volatile int       stop;


#define ROTL(x, b)  (((x) << (b)) | ((x) >> (64 - (b))))
#define ROUND(v0, v1, v2, v3)                                               \
    do {                                                                    \
        v0 += v1; v1 = ROTL(v1, 13); v1 ^= v0; v0 = ROTL(v0, 32);           \
        v2 += v3; v3 = ROTL(v3, 16); v3 ^= v2;                              \
        v0 += v3; v3 = ROTL(v3, 21); v3 ^= v0;                              \
        v2 += v1; v1 = ROTL(v1, 17); v1 ^= v2; v2 = ROTL(v2, 32);           \
    } while (0)


/* SipHash-1-3 of five words, as vg_syn_hash() in voidgate.bpf.c */
static uint64_t
sip13(const uint64_t m[5])
{
    uint64_t v0 = K0 ^ 0x736f6d6570736575ULL;
    uint64_t v1 = K1 ^ 0x646f72616e646f6dULL;
    uint64_t v2 = K0 ^ 0x6c7967656e657261ULL;
    uint64_t v3 = K1 ^ 0x7465646279746573ULL;
    uint64_t b = 40ULL << 56;
    int i;

    for (i = 0; i < 5; i++) {
        v3 ^= m[i];
        ROUND(v0, v1, v2, v3);
        v0 ^= m[i];
    }

    v3 ^= b;
    ROUND(v0, v1, v2, v3);
    v0 ^= b;
    v2 ^= 0xff;
    ROUND(v0, v1, v2, v3);
    ROUND(v0, v1, v2, v3);
    ROUND(v0, v1, v2, v3);

    return v0 ^ v1 ^ v2 ^ v3;
}


/* a SYN to LOCAL:80 from 10.0.<cpu>.<i>, sequence number cpu << 8 | i;
 * its three bits set in want, as the filter sets them with one block
 */
static void
syn(unsigned char *buf, int cpu, int i, struct vg_syn_block *want)
{
    struct ethhdr  *eth = (struct ethhdr *) buf;
    struct iphdr   *ip = (struct iphdr *) (eth + 1);
    struct tcphdr  *tcp = (struct tcphdr *) (ip + 1);
    uint64_t        m[5] = { 0 }, h;
    uint32_t        o;
    int             k;

    memset(buf, 0, FRAME_LEN);
    eth->h_proto = htons(ETH_P_IP);
    ip->version = 4;
    ip->ihl = 5;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->tot_len = htons(FRAME_LEN - sizeof(*eth));
    ip->saddr = htonl(0x0a000000 | cpu << 8 | i);
    inet_pton(AF_INET, LOCAL, &ip->daddr);
    tcp->source = htons(40000);
    tcp->dest = htons(80);
    tcp->seq = htonl((uint32_t) (cpu << 8 | i));
    tcp->doff = 5;
    tcp->syn = 1;

    /* the key as vg_judge() makes it, from the bytes as in the packet */
    m[0] = (uint64_t) ip->saddr << 32 | ip->daddr;
    m[1] = (uint64_t) tcp->source << 48 | (uint64_t) tcp->dest << 32
           | tcp->seq;
    h = sip13(m);

    for (k = 0; k < 3; k++) {
        o = (h >> (k * VG_SYN_BLOCK_LOG2)) & (VG_SYN_BLOCK_BITS - 1);
        want->w[o >> 6] |= 1ULL << (o & 63);
    }
}


static void *
work(void *arg)
{
    worker_t *w = arg;
    cpu_set_t set;
    int i;

    CPU_ZERO(&set);
    CPU_SET(w->cpu, &set);
    pthread_setaffinity_np(pthread_self(), sizeof(set), &set);

    for ( ;; ) {
        pthread_barrier_wait(&start);

        if (stop) {
            return NULL;
        }

        for (i = 0; i < SYNS; i++) {
            LIBBPF_OPTS(bpf_test_run_opts, o, .data_in = w->frames[i],
                        .data_size_in = FRAME_LEN, .repeat = 1);

            bpf_prog_test_run_opts(w->prog, &o);
        }

        pthread_barrier_wait(&done);
    }
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


int
main(int argc, char **argv)
{
    struct voidgate_bpf  *s;
    struct vg_syn_block   want, *bloom;
    struct vg_syn_marks  *marks;
    struct vg_lpm_v4      lk = { .prefixlen = 32 };
    struct vg_cfg         c = { .armed = 1, .syn_guard = 1,
                                .syn_engaged = 1 };
    struct bpf_program   *p;
    static worker_t       w[MAX_CPUS];
    pthread_t             t[MAX_CPUS];
    uint64_t              g;
    uint32_t              key = 0;
    uint8_t               one = 1;
    long                  rounds = 20000, r, lossy = 0, lost = 0, skipped = 0;
    int                   plain = 0, ncpus, i, j, prog, word;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0) {
            plain = 1;
            gen_clock = CLOCK_MONOTONIC;

        } else {
            rounds = atol(argv[i]);
        }
    }

    ncpus = (int) sysconf(_SC_NPROCESSORS_ONLN);

    if (ncpus > MAX_CPUS) {
        ncpus = MAX_CPUS;
    }

    if (ncpus < 2) {
        printf("syn-bits: one CPU, nothing to race: skipped\n");
        return 0;
    }

    s = voidgate_bpf__open();

    if (s == NULL) {
        fprintf(stderr, "open: %s\n", strerror(errno));
        return 1;
    }

    /* one block a slot: every SYN writes the same cache line */
    bpf_map__set_max_entries(s->maps.syn_bloom, VG_SYN_SLOTS);
    s->rodata->vg_syn_blocks_log2 = 0;
    s->rodata->vg_syn_k0 = K0;
    s->rodata->vg_syn_k1 = K1;

    p = plain ? s->progs.voidgate_xdp_pl : s->progs.voidgate_xdp;
    bpf_program__set_autoload(s->progs.voidgate_xdp, !plain);
    bpf_program__set_autoload(s->progs.voidgate_xdp_pl, plain);
    bpf_program__set_autoload(s->progs.voidgate_tc, false);
    bpf_program__set_autoload(s->progs.voidgate_tc_pl, false);

    if (voidgate_bpf__load(s) != 0) {
        fprintf(stderr, "load: %s\n", strerror(errno));
        return 1;
    }

    prog = bpf_program__fd(p);
    inet_pton(AF_INET, LOCAL, lk.data);
    bpf_map_update_elem(bpf_map__fd(s->maps.local_v4), &lk, &one, 0);
    bpf_map_update_elem(bpf_map__fd(s->maps.cfg), &key, &c, 0);

    bloom = mmap(NULL, VG_SYN_SLOTS * sizeof(*bloom), PROT_READ | PROT_WRITE,
                 MAP_SHARED, bpf_map__fd(s->maps.syn_bloom), 0);
    marks = mmap(NULL, sizeof(*marks), PROT_READ | PROT_WRITE, MAP_SHARED,
                 bpf_map__fd(s->maps.syn_marks), 0);

    if (bloom == MAP_FAILED || marks == MAP_FAILED) {
        fprintf(stderr, "mmap: %s\n", strerror(errno));
        return 1;
    }

    memset(&want, 0, sizeof(want));

    for (i = 0; i < ncpus; i++) {
        w[i].cpu = i;
        w[i].prog = prog;

        for (j = 0; j < SYNS; j++) {
            syn(w[i].frames[j], i, j, &want);
        }
    }

    pthread_barrier_init(&start, NULL, (unsigned) ncpus + 1);
    pthread_barrier_init(&done, NULL, (unsigned) ncpus + 1);

    for (i = 0; i < ncpus; i++) {
        pthread_create(&t[i], NULL, work, &w[i]);
    }

    for (r = 0; r < rounds; r++) {
        /*
         * the slot of this generation, cleared and marked for it, and no
         * other: an older one, full, would make every SYN a retransmission,
         * and nothing would be written
         */
        g = gen_now();

        for (i = 0; i < VG_SYN_SLOTS; i++) {
            __atomic_store_n(&marks->gen[i], VG_SYN_MARK_NONE,
                             __ATOMIC_RELAXED);
        }

        memset(&bloom[g % VG_SYN_SLOTS], 0, sizeof(*bloom));
        __atomic_store_n(&marks->gen[g % VG_SYN_SLOTS], g, __ATOMIC_RELEASE);

        pthread_barrier_wait(&start);
        pthread_barrier_wait(&done);

        /* a generation boundary inside the round: some went elsewhere */
        if (gen_now() != g) {
            skipped++;
            continue;
        }

        i = 0;

        for (word = 0; word < VG_SYN_BLOCK_BITS / 64; word++) {
            i += __builtin_popcountll(want.w[word]
                                      & ~bloom[g % VG_SYN_SLOTS].w[word]);
        }

        if (i > 0) {
            lossy++;
            lost += i;
        }
    }

    stop = 1;
    pthread_barrier_wait(&start);

    for (i = 0; i < ncpus; i++) {
        pthread_join(t[i], NULL);
    }

    printf("syn-bits: %s, %d CPUs x %d SYNs, %ld rounds (%ld across a "
           "boundary, not judged): %ld with bits lost, %ld bits\n",
           plain ? "plain writes" : "atomic OR", ncpus, SYNS, rounds,
           skipped, lossy, lost);

    voidgate_bpf__destroy(s);

    return !plain && lost > 0;
}
