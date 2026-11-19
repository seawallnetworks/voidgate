/* SPDX-License-Identifier: Apache-2.0 */

/*
 * First-SYN drop's userspace side (Seawall proposal 0023 §2): a thread
 * that, while the gate is armed, zeroes the slot the next generation
 * will use, then marks it for that generation, with release. BPF writes
 * a slot only once its mark is the current generation, so a slot is
 * never zeroed under a writer, and the marks are written here alone.
 * The thread needs no precise timer: it has a generation, 0.9 s, to
 * clear the next slot. Late, BPF passes SYNs unfiltered (fail-open).
 */

#include "syn_guard.h"
#include "log.h"

#include <bpf/bpf.h>
#include <errno.h>
#include <linux/bpf.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>


/*
 * Past a boundary before clearing: more than a tick (10 ms at HZ=100), so
 * the coarse clock BPF reads has moved too. Ahead of BPF, the thread
 * would clear a slot BPF still reads.
 */
#define VG_SYN_WAKE_NS  20000000ULL


struct vg_syn {
    struct vg_syn_block  *bloom;
    uint32_t              blocks_log2;
    struct vg_syn_marks  *marks;
    clockid_t             clock;
    pthread_t             thread;
    pthread_mutex_t       lock;
    pthread_cond_t        cond;
    int                   armed;
    int                   stop;
};


static void *syn_run(void *arg);
static void syn_ready(struct vg_syn *s, uint64_t g);
static uint64_t syn_gen_now(struct vg_syn *s);


/*
 * Does this kernel's verifier take an atomic OR (Linux 5.12, "bpf: Add
 * bitwise atomic instructions"), and bpf_ktime_get_coarse_ns() (5.11),
 * which the same entries read? One before refuses a program that has an
 * atomic OR anywhere, so voidgate loads the entries without it there.
 * VG_SYN_ATOMIC=0 takes those anyway, for the tests.
 */
int
vg_syn_atomic_probe(void)
{
    const char *env;
    int fd;
    struct bpf_insn insns[] = {
        { .code = BPF_JMP | BPF_CALL, .imm = BPF_FUNC_ktime_get_coarse_ns },
        { .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0 },
        { .code = BPF_STX | BPF_DW | BPF_MEM, .dst_reg = BPF_REG_10,
          .src_reg = BPF_REG_0, .off = -8 },
        { .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_1,
          .imm = 1 },
        { .code = BPF_STX | BPF_DW | BPF_ATOMIC, .dst_reg = BPF_REG_10,
          .src_reg = BPF_REG_1, .off = -8, .imm = BPF_OR },
        { .code = BPF_JMP | BPF_EXIT },
    };

    env = getenv("VG_SYN_ATOMIC");

    if (env != NULL && strcmp(env, "0") == 0) {
        return 0;
    }

    fd = bpf_prog_load(BPF_PROG_TYPE_XDP, "vg_atomic_or", "GPL", insns,
                       sizeof(insns) / sizeof(insns[0]), NULL);

    if (fd < 0) {
        return 0;
    }

    close(fd);

    return 1;
}


/*
 * coarse: the atomic entries are loaded, which read the generation from
 * bpf_ktime_get_coarse_ns(), CLOCK_MONOTONIC_COARSE; the plain ones read
 * bpf_ktime_get_ns(), CLOCK_MONOTONIC.
 */
struct vg_syn *
vg_syn_start(struct vg_syn_block *bloom, uint32_t blocks_log2,
    struct vg_syn_marks *marks, int coarse)
{
    pthread_condattr_t ca;
    sigset_t all, old;
    struct vg_syn *s;
    int i, err;

    s = calloc(1, sizeof(*s));

    if (s == NULL) {
        return NULL;
    }

    s->bloom = bloom;
    s->blocks_log2 = blocks_log2;
    s->marks = marks;
    s->clock = coarse ? CLOCK_MONOTONIC_COARSE : CLOCK_MONOTONIC;

    /* a slot cleared for no generation: none from the clock is this */
    for (i = 0; i < VG_SYN_SLOTS; i++) {
        __atomic_store_n(&marks->gen[i], VG_SYN_MARK_NONE, __ATOMIC_RELEASE);
    }

    pthread_mutex_init(&s->lock, NULL);
    pthread_condattr_init(&ca);
    pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
    pthread_cond_init(&s->cond, &ca);
    pthread_condattr_destroy(&ca);

    /*
     * Every signal blocked in the thread, which inherits the mask: a
     * SIGTERM it took would set the flag, but not wake the main loop's
     * poll(), and shutdown would wait for its timeout
     */
    sigfillset(&all);
    pthread_sigmask(SIG_SETMASK, &all, &old);
    err = pthread_create(&s->thread, NULL, syn_run, s);
    pthread_sigmask(SIG_SETMASK, &old, NULL);

    if (err != 0) {
        sw_log_warn("syn_guard: thread: %s", strerror(err));
        pthread_cond_destroy(&s->cond);
        pthread_mutex_destroy(&s->lock);
        free(s);
        return NULL;
    }

    return s;
}


/* The gate armed or not: the thread clears while it is, never idle. */
void
vg_syn_armed(struct vg_syn *s, int armed)
{
    if (s == NULL) {
        return;
    }

    pthread_mutex_lock(&s->lock);

    if (s->armed != armed) {
        s->armed = armed;
        pthread_cond_signal(&s->cond);
    }

    pthread_mutex_unlock(&s->lock);
}


void
vg_syn_stop(struct vg_syn *s)
{
    if (s == NULL) {
        return;
    }

    pthread_mutex_lock(&s->lock);
    s->stop = 1;
    pthread_cond_signal(&s->cond);
    pthread_mutex_unlock(&s->lock);

    pthread_join(s->thread, NULL);
    pthread_cond_destroy(&s->cond);
    pthread_mutex_destroy(&s->lock);
    free(s);
}


/*
 * Armed, at each generation's start: the current slot and the next
 * cleared for theirs. The current one is only on arming, or after a late
 * wake; until then BPF passed its SYNs unfiltered and wrote nothing
 * there. The next one holds generation g - 5, which BPF no longer reads.
 */
static void *
syn_run(void *arg)
{
    struct vg_syn *s = arg;
    struct timespec ts;
    uint64_t g, next;

    pthread_mutex_lock(&s->lock);

    while (!s->stop) {
        if (!s->armed) {
            pthread_cond_wait(&s->cond, &s->lock);
            continue;
        }

        pthread_mutex_unlock(&s->lock);

        g = syn_gen_now(s);
        syn_ready(s, g);
        syn_ready(s, g + 1);

        /* the wait on CLOCK_MONOTONIC, never behind the coarse clock */
        next = (g + 1) * VG_SYN_GEN_NS + VG_SYN_WAKE_NS;
        ts.tv_sec = (time_t) (next / 1000000000ULL);
        ts.tv_nsec = (long) (next % 1000000000ULL);

        pthread_mutex_lock(&s->lock);

        if (!s->stop && s->armed) {
            pthread_cond_timedwait(&s->cond, &s->lock, &ts);
        }
    }

    pthread_mutex_unlock(&s->lock);

    return NULL;
}


/* Generation g's slot zeroed, then marked for g, unless it is already. */
static void
syn_ready(struct vg_syn *s, uint64_t g)
{
    uint32_t slot = (uint32_t) (g % VG_SYN_SLOTS);
    size_t blocks = (size_t) 1 << s->blocks_log2;

    if (__atomic_load_n(&s->marks->gen[slot], __ATOMIC_RELAXED) == g) {
        return;
    }

    memset(s->bloom + (size_t) slot * blocks, 0,
           blocks * sizeof(struct vg_syn_block));

    /* the zeroes before the mark, for BPF on another CPU, on arm64 too */
    __atomic_store_n(&s->marks->gen[slot], g, __ATOMIC_RELEASE);
}


/* The generation now, as BPF computes it from the same clock. */
static uint64_t
syn_gen_now(struct vg_syn *s)
{
    struct timespec ts;

    clock_gettime(s->clock, &ts);

    return ((uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec)
           / VG_SYN_GEN_NS;
}
