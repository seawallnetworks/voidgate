
/* SPDX-License-Identifier: Apache-2.0 */

#include "maps.h"
#include "log.h"

#include "bpf/voidgate.skel.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include <errno.h>
#include <stdarg.h>
#include <linux/if_link.h>
#include <linux/magic.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <sw_flowd/sw_flowd.h>

/* tcx is Linux 6.6's UAPI: with older headers, such as Amazon Linux
 * 2023's 6.1, voidgate still attaches with tcx on a kernel that has it.
 */
#ifndef BPF_F_BEFORE
#define BPF_F_BEFORE  (1U << 3)
#define BPF_TCX_INGRESS  46
#endif

/* voidgate's classic TC filter, on a kernel without tcx: a priority
 * before most others (mini-fw's is 0xc000), so it runs first, as tcx's
 * BPF_F_BEFORE and the XDP dispatcher's order have it.
 */
#define VG_TC_HANDLE  0x5647  /* "VG" */
#define VG_TC_PRIORITY  0x0100

#define VG_XDP_PROG  "voidgate_xdp"

/* xdp_claim(): what holds the XDP hook */
#define VG_XDP_FREE  0
#define VG_XDP_HELD  1      /* a program, not libxdp's dispatcher */
#define VG_XDP_SHARED  2    /* libxdp's dispatcher */


/* set around a call that may fail, harmlessly: libbpf keeps quiet */
static int libbpf_quiet;

static void bump_memlock(void);
static int libbpf_print(enum libbpf_print_level level, const char *fmt,
    va_list args);
static int libxdp_print(enum libxdp_print_level level, const char *fmt,
    va_list args);
static int skel_open(struct vg_maps *m, const struct vg_config *cfg);
static int skel_fresh(struct vg_maps *m, const struct vg_config *cfg);
static const char *bpffs_dir(void);
static int bpffs_mounted(void);
static int have_tcx(void);
static int xdp_claim(int ifindex, char *holder, size_t len,
    enum xdp_attach_mode *mode);
static int attach_xdp(struct vg_maps *m, const struct vg_config *cfg,
    enum xdp_attach_mode mode);
static int attach_tc(struct vg_maps *m, const struct vg_config *cfg);
static void tc_detach(int ifindex);
static size_t sum_scratch_need(int ncpus);
static int foreach_family(struct vg_maps *m, int fd, int family, size_t ksz,
    uint32_t budget, vg_remote_pt fn, void *ctx);
static int lpm_update(int fd, const struct vg_cidr *p, const void *val);
static int lpm_delete(int fd, const struct vg_cidr *p);
static int flush_lpm(int fd, int v6);
static void flows_open(struct vg_maps *m);

static void
bump_memlock(void)
{
    struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };

    if (setrlimit(RLIMIT_MEMLOCK, &r) < 0) {
        sw_log_warn("setrlimit(RLIMIT_MEMLOCK) failed: %s", strerror(errno));
    }
}


static int
libbpf_print(enum libbpf_print_level level, const char *fmt,
    va_list args)
{
    enum libbpf_print_level max_level =
        vg_verbose >= 2 ? LIBBPF_INFO : LIBBPF_WARN;

    if (level > max_level || libbpf_quiet) {
        return 0;
    }

    /* the sections of libxdp's objects that libxdp reads itself */
    if (strstr(fmt, "skipping unrecognized data section") != NULL) {
        return 0;
    }

    return vfprintf(stderr, fmt, args);
}


static int
libxdp_print(enum libxdp_print_level level, const char *fmt,
    va_list args)
{
    enum libxdp_print_level max_level =
        vg_verbose >= 2 ? LIBXDP_INFO : LIBXDP_WARN;

    if (level > max_level) {
        return 0;
    }

    return vfprintf(stderr, fmt, args);
}


static size_t
sum_scratch_need(int ncpus)
{
    size_t a = sizeof(struct host_counters);
    size_t b = sizeof(struct vg_metrics);
    size_t c = sizeof(struct sf_stats);

    if (c > b) {
        b = c;
    }

    return (size_t) ncpus * (a > b ? a : b);
}


/* Opens the object; vg_attach() loads the entry for the hook it takes. */
int
vg_maps_open(struct vg_maps *m, struct vg_config *cfg)
{
    memset(m, 0, sizeof(*m));

    m->ifindex = (int) if_nametoindex(cfg->interface);
    m->tcx_fd = -1;
    m->flows_fd = -1;
    m->flows_config_fd = -1;
    m->flows_stats_fd = -1;

    bump_memlock();
    libbpf_set_print(libbpf_print);
    libxdp_set_print(libxdp_print);

    m->ncpus = libbpf_num_possible_cpus();

    if (m->ncpus <= 0) {
        m->ncpus = 1;
    }

    /* Reuse one buffer sized for either counter type across all CPUs. */
    m->sum_scratch_size = sum_scratch_need(m->ncpus);
    m->sum_scratch = calloc(1, m->sum_scratch_size);

    if (m->sum_scratch == NULL) {
        sw_log_fatal("out of memory");
    }

    flows_open(m);

    if (skel_open(m, cfg) < 0) {
        free(m->sum_scratch);
        m->sum_scratch = NULL;
        sw_log_fatal("failed to open BPF object");
    }

    return 0;
}


static int
skel_open(struct vg_maps *m, const struct vg_config *cfg)
{
    m->skel = voidgate_bpf__open();

    if (m->skel == NULL) {
        return -1;
    }

    if (cfg->remote_map_size) {
        bpf_map__set_max_entries(m->skel->maps.remote_v4, cfg->remote_map_size);
        bpf_map__set_max_entries(m->skel->maps.remote_v6, cfg->remote_map_size);
    }

    if (cfg->drop_map_size) {
        bpf_map__set_max_entries(m->skel->maps.drop_v4, cfg->drop_map_size);
        bpf_map__set_max_entries(m->skel->maps.drop_v6, cfg->drop_map_size);
    }

    /* sw_flowd's table, as flows_open() found it */
    if (m->flows_fd >= 0
        && (bpf_map__reuse_fd(m->skel->maps.flows, m->flows_fd) != 0
            || bpf_map__reuse_fd(m->skel->maps.flows_config,
                                 m->flows_config_fd) != 0))
    {
        sw_log_warn("sw_flowd's flow table: %s", strerror(errno));
        voidgate_bpf__destroy(m->skel);
        m->skel = NULL;
        return -1;
    }

    return 0;
}


/* An object is loaded once: after a failed attach that loaded it, the
 * next attempt starts from a new one.
 */
static int
skel_fresh(struct vg_maps *m, const struct vg_config *cfg)
{
    if (bpf_program__fd(m->skel->progs.voidgate_xdp) < 0
        && bpf_program__fd(m->skel->progs.voidgate_tc) < 0)
    {
        return 0;
    }

    voidgate_bpf__destroy(m->skel);

    if (skel_open(m, cfg) < 0) {
        m->skel = NULL;
        sw_log_warn("failed to open BPF object");
        return -1;
    }

    return 0;
}


void
vg_maps_close(struct vg_maps *m)
{
    if (m == NULL) {
        return;
    }

    vg_detach(m);

    if (m->flows_fd >= 0) {
        close(m->flows_fd);
        close(m->flows_config_fd);
        m->flows_fd = -1;
        m->flows_config_fd = -1;
    }

    if (m->flows_stats_fd >= 0) {
        close(m->flows_stats_fd);
        m->flows_stats_fd = -1;
    }

    if (m->skel != NULL) {
        voidgate_bpf__destroy(m->skel);
        m->skel = NULL;
    }

    free(m->sum_scratch);
    m->sum_scratch = NULL;
}


/* Where voidgate runs, as Seawall's proposal 0004 has it: in
 * libxdp's dispatcher, first of the programs there; at TC ingress, first,
 * when a program that is not a dispatcher holds the XDP hook, which is
 * never taken from it. hook = xdp or tc pins one of them.
 */
int
vg_attach(struct vg_maps *m, const struct vg_config *cfg)
{
    enum xdp_attach_mode mode, shared_mode = XDP_MODE_UNSPEC;
    char holder[BPF_OBJ_NAME_LEN];
    int automode, held, err;

    if (m->skel == NULL) {
        sw_log_warn("attach: BPF object not open");
        return -1;
    }

    automode = 0;

    if (strcmp(cfg->xdp_mode, "native") == 0) {
        mode = XDP_MODE_NATIVE;

    } else if (strcmp(cfg->xdp_mode, "skb") == 0) {
        mode = XDP_MODE_SKB;

    } else {
        if (strcmp(cfg->xdp_mode, "auto") != 0) {
            sw_log_warn("xdp_mode %s: not auto, native or skb; taking auto",
                        cfg->xdp_mode);
        }

        mode = XDP_MODE_NATIVE;
        automode = 1;
    }

    if (strcmp(cfg->hook, "auto") != 0 && strcmp(cfg->hook, "xdp") != 0
        && strcmp(cfg->hook, "tc") != 0)
    {
        sw_log_warn("hook %s: not auto, xdp or tc", cfg->hook);
        return -1;
    }

    /* A filter left by a daemon that died at classic TC would go on
     * judging with its own drop list, whichever hook this one takes. A
     * tcx link went with the daemon.
     */
    tc_detach(m->ifindex);

    if (strcmp(cfg->hook, "tc") == 0) {
        return attach_tc(m, cfg);
    }

    /* Without bpffs libxdp attaches the program alone, not in a
     * dispatcher, and every program after it finds the hook held.
     */
    if (!bpffs_mounted()) {
        sw_log_warn("XDP attach: no bpffs at %s, which libxdp needs to share "
                    "the hook", bpffs_dir());
        return -1;
    }

    held = xdp_claim(m->ifindex, holder, sizeof(holder), &shared_mode);

    if (held < 0) {
        sw_log_warn("XDP attach: reading ifindex %d's XDP programs: %s",
                    m->ifindex, strerror(-held));
        return -1;
    }

    /* a dispatcher has one mode, which joining it keeps */
    if (held == VG_XDP_SHARED && automode) {
        mode = shared_mode;
        automode = 0;
    }

    if (held != VG_XDP_HELD) {
        err = attach_xdp(m, cfg, mode);

        /* A driver may have native XDP and still refuse it: ENA, say, at
         * an MTU over 3498.
         */
        if (err && automode && err != -EBUSY && err != -EEXIST) {
            sw_log_warn("native XDP attach failed (%s), falling back to skb",
                        strerror(-err));
            err = attach_xdp(m, cfg, XDP_MODE_SKB);
        }

        if (err == 0) {
            return 0;
        }

        /* attached between xdp_claim() and here */
        if (err != -EBUSY && err != -EEXIST) {
            sw_log_warn("XDP attach failed: %s", strerror(-err));
            return -1;
        }

        snprintf(holder, sizeof(holder), "another program");
    }

    if (strcmp(cfg->hook, "xdp") == 0) {
        sw_log_warn("XDP attach: %s holds ifindex %d's XDP hook without "
                    "libxdp's dispatcher", holder, m->ifindex);
        return -1;
    }

    sw_log_warn("degraded: %s holds ifindex %d's XDP hook without libxdp's "
                "dispatcher; judging at TC ingress, which costs more per drop",
                holder, m->ifindex);
    m->degraded = 1;

    return attach_tc(m, cfg);
}


void
vg_detach(struct vg_maps *m)
{
    if (m->hook == VG_HOOK_XDP) {
        xdp_program__detach(m->xdp_prog, m->ifindex, m->xdp_mode, 0);
        xdp_program__close(m->xdp_prog);
        m->xdp_prog = NULL;

    } else if (m->hook == VG_HOOK_TC) {
        if (m->tcx_fd >= 0) {
            close(m->tcx_fd);
            m->tcx_fd = -1;

        } else {
            tc_detach(m->ifindex);
        }

    } else {
        return;
    }

    sw_log_info("detached %s from ifindex %d", vg_hook_name(m), m->ifindex);
    m->hook = VG_HOOK_NONE;
}


const char *
vg_hook_name(const struct vg_maps *m)
{
    switch (m->hook) {
    case VG_HOOK_XDP:
        return m->xdp_mode == XDP_MODE_NATIVE ? "xdp-native"
               : m->xdp_mode == XDP_MODE_HW ? "xdp-hw" : "xdp-skb";
    case VG_HOOK_TC:
        return m->tcx_fd >= 0 ? "tcx" : "tc";
    default:
        return "none";
    }
}


static const char *
bpffs_dir(void)
{
    const char *dir = getenv("LIBXDP_BPFFS");

    return dir != NULL ? dir : "/sys/fs/bpf";
}


static int
bpffs_mounted(void)
{
    struct statfs st;

    return statfs(bpffs_dir(), &st) == 0 && st.f_type == BPF_FS_MAGIC;
}


/* tcx (6.6+): a kernel without it refuses to query it. VG_NO_TCX=1 takes
 * classic TC anyway, to test it on a newer kernel.
 */
static int
have_tcx(void)
{
    LIBBPF_OPTS(bpf_prog_query_opts, q);

    if (getenv("VG_NO_TCX") != NULL) {
        return 0;
    }

    return bpf_prog_query_opts(1 /* lo */, BPF_TCX_INGRESS, &q) == 0;
}


/* Takes voidgate's own XDP programs off the hook, left by a daemon that
 * died without detaching: alone (an older voidgate), or in a dispatcher.
 * Then returns VG_XDP_FREE; VG_XDP_SHARED, with the dispatcher's mode; or
 * VG_XDP_HELD, with the name of the program that holds the hook; or
 * -errno.
 */
static int
xdp_claim(int ifindex, char *holder, size_t len,
    enum xdp_attach_mode *mode)
{
    struct xdp_multiprog *mp;
    struct xdp_program *p;
    long err;

    for ( ;; ) {
        mp = xdp_multiprog__get_from_ifindex(ifindex);
        err = libxdp_get_error(mp);

        if (err == -ENOENT) {
            return VG_XDP_FREE;
        }

        if (err) {
            return (int) err;
        }

        if (xdp_multiprog__is_legacy(mp)) {
            p = xdp_multiprog__main_prog(mp);

            if (p == NULL) {
                /* only a hardware-offloaded program */
                xdp_multiprog__close(mp);
                return VG_XDP_FREE;
            }

            if (strcmp(xdp_program__name(p), VG_XDP_PROG) != 0) {
                snprintf(holder, len, "%s", xdp_program__name(p));
                xdp_multiprog__close(mp);
                return VG_XDP_HELD;
            }

            sw_log_warn("removing a voidgate XDP program left on ifindex %d",
                        ifindex);
            err = xdp_multiprog__detach(mp);
            xdp_multiprog__close(mp);

            if (err) {
                return (int) err;
            }

            continue;
        }

        for (p = xdp_multiprog__next_prog(NULL, mp); p != NULL;
             p = xdp_multiprog__next_prog(p, mp))
        {
            if (strcmp(xdp_program__name(p), VG_XDP_PROG) == 0) {
                break;
            }
        }

        if (p == NULL) {
            *mode = xdp_multiprog__attach_mode(mp);
            xdp_multiprog__close(mp);
            return VG_XDP_SHARED;
        }

        /* one at a time: a detach replaces the dispatcher */
        sw_log_warn("removing a voidgate XDP program left in ifindex %d's "
                    "dispatcher", ifindex);
        err = xdp_program__detach(p, ifindex,
                                  xdp_multiprog__attach_mode(mp), 0);
        xdp_multiprog__close(mp);

        if (err) {
            return (int) err;
        }
    }
}


/* libxdp loads the object: the XDP entry, as an extension of the
 * dispatcher it makes or joins. Returns 0 or -errno.
 */
static int
attach_xdp(struct vg_maps *m, const struct vg_config *cfg,
    enum xdp_attach_mode mode)
{
    DECLARE_LIBXDP_OPTS(xdp_program_opts, opts,
                        .prog_name = VG_XDP_PROG);
    struct xdp_multiprog *mp;
    struct xdp_program *xp;
    long err;

    if (skel_fresh(m, cfg) < 0) {
        return -ENOMEM;
    }

    opts.obj = m->skel->obj;
    bpf_program__set_autoload(m->skel->progs.voidgate_tc, false);

    xp = xdp_program__create(&opts);
    err = libxdp_get_error(xp);

    if (err) {
        return (int) err;
    }

    /* xdp.frags is not enough for libxdp, which then makes a dispatcher
     * without frags: one a jumbo-MTU interface refuses.
     */
    xdp_program__set_xdp_frags_support(xp, true);

    err = xdp_program__attach(xp, m->ifindex, mode, 0);

    if (err) {
        xdp_program__close(xp);
        return (int) err;
    }

    m->hook = VG_HOOK_XDP;
    m->xdp_prog = xp;
    m->xdp_mode = mode;

    mp = xdp_multiprog__get_from_ifindex(m->ifindex);

    if (libxdp_get_error(mp) == 0) {
        m->xdp_mode = xdp_multiprog__attach_mode(mp);

        if (xdp_multiprog__is_legacy(mp)) {
            sw_log_warn("XDP: libxdp attached voidgate without a dispatcher; "
                        "no other program can share the hook");
        }

        xdp_multiprog__close(mp);
    }

    sw_log_info("attached %s on ifindex %d", vg_hook_name(m), m->ifindex);

    return 0;
}


static int
attach_tc(struct vg_maps *m, const struct vg_config *cfg)
{
    LIBBPF_OPTS(bpf_link_create_opts, lopts, .flags = BPF_F_BEFORE);
    LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = m->ifindex,
                .attach_point = BPF_TC_INGRESS);
    LIBBPF_OPTS(bpf_tc_opts, topts, .handle = VG_TC_HANDLE,
                .priority = VG_TC_PRIORITY, .flags = BPF_TC_F_REPLACE);
    int prog_fd, fd, err;

    if (skel_fresh(m, cfg) < 0) {
        return -1;
    }

    bpf_program__set_autoload(m->skel->progs.voidgate_xdp, false);
    bpf_program__set_autoload(m->skel->progs.voidgate_tc, true);

    err = voidgate_bpf__load(m->skel);

    if (err) {
        sw_log_warn("failed to load BPF object: %d", err);
        return -1;
    }

    prog_fd = bpf_program__fd(m->skel->progs.voidgate_tc);

    if (have_tcx()) {
        /* first: ahead of mini-fw, which appends */
        fd = bpf_link_create(prog_fd, m->ifindex, BPF_TCX_INGRESS, &lopts);

        if (fd < 0) {
            sw_log_warn("tcx attach failed: %s", strerror(errno));
            return -1;
        }

        m->tcx_fd = fd;

    } else {
        /* the clsact qdisc may be there already, mini-fw's or another's */
        err = bpf_tc_hook_create(&hook);

        if (err && err != -EEXIST) {
            sw_log_warn("clsact qdisc: %s", strerror(-err));
            return -1;
        }

        topts.prog_fd = prog_fd;
        err = bpf_tc_attach(&hook, &topts);

        if (err) {
            sw_log_warn("TC attach failed: %s", strerror(-err));
            return -1;
        }
    }

    m->hook = VG_HOOK_TC;
    sw_log_info("attached %s on ifindex %d%s", vg_hook_name(m), m->ifindex,
                m->degraded ? " (degraded)" : "");

    return 0;
}


/* The clsact qdisc is left: something else may use it. There may be no
 * filter, or no qdisc, to detach from.
 */
static void
tc_detach(int ifindex)
{
    LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex,
                .attach_point = BPF_TC_INGRESS);
    LIBBPF_OPTS(bpf_tc_opts, opts, .handle = VG_TC_HANDLE,
                .priority = VG_TC_PRIORITY);

    libbpf_quiet = 1;
    bpf_tc_detach(&hook, &opts);
    libbpf_quiet = 0;
}


int
vg_maps_metrics_fd(struct vg_maps *m)
{
    return bpf_map__fd(m->skel->maps.metrics);
}


int
vg_maps_remote_v4_fd(struct vg_maps *m)
{
    return bpf_map__fd(m->skel->maps.remote_v4);
}


int
vg_maps_remote_v6_fd(struct vg_maps *m)
{
    return bpf_map__fd(m->skel->maps.remote_v6);
}


static int
foreach_family(struct vg_maps *m, int fd, int family, size_t ksz,
    uint32_t budget, vg_remote_pt fn, void *ctx)
{
    uint8_t cur[16], next[16];
    int first = 1;
    uint32_t visited = 0;

    if (fd < 0) {
        return -1;
    }

    memset(cur, 0, sizeof(cur));
    memset(next, 0, sizeof(next));
    while (visited < budget
           && bpf_map_get_next_key(fd, first ? NULL : cur, next) == 0)
    {
        struct host_counters sum;

        first = 0;
        memcpy(cur, next, ksz);
        visited++;

        if (vg_sum_percpu(m, fd, cur, sizeof(sum), &sum) == 0) {
            fn(family, cur, &sum, ctx);
        }
    }

    if (visited < budget) {
        return 1;
    }

    if (bpf_map_get_next_key(fd, first ? NULL : cur, next) != 0) {
        return 1;
    }

    return 0;
}


int
vg_remote_foreach(struct vg_maps *m, uint32_t budget, vg_remote_pt fn,
    void *ctx)
{
    int c4, c6;

    if (m == NULL || fn == NULL) {
        return -1;
    }

    if (budget == 0) {
        budget = VG_REMOTE_MAP_MAX;
    }

    c4 = foreach_family(m, vg_maps_remote_v4_fd(m), AF_INET, 4, budget, fn,
                        ctx);
    c6 = foreach_family(m, vg_maps_remote_v6_fd(m), AF_INET6, 16, budget, fn,
                        ctx);

    if (c4 < 0 || c6 < 0) {
        return -1;
    }

    return c4 && c6;
}


int
vg_cfg_commit(struct vg_maps *m, uint32_t armed,
    const struct vg_config *cfg)
{
    __u32 key = 0;
    struct vg_cfg bc;
    int i, fd;

    memset(&bc, 0, sizeof(bc));
    bc.armed = armed;

    if (cfg != NULL) {
        bc.allow_port_count = (uint16_t) cfg->allow_port_count;

        if (bc.allow_port_count > VG_MAX_ALLOW_PORTS) {
            bc.allow_port_count = VG_MAX_ALLOW_PORTS;
        }

        for (i = 0; i < bc.allow_port_count; i++) {
            bc.allow_ports[i] = cfg->allow_ports[i];
        }

        bc.reply_idle_ns = (uint64_t) cfg->reply_idle_seconds
                              * 1000000000ULL;
    }

    fd = bpf_map__fd(m->skel->maps.cfg);

    return bpf_map_update_elem(fd, &key, &bc, BPF_ANY);
}


int
vg_sum_percpu(struct vg_maps *m, int map_fd, const void *key,
    size_t val_size, void *out_sum)
{
    int ncpus = m->ncpus;
    uint8_t *buf;
    size_t need, i, words;
    int cpu;

    if (ncpus <= 0) {
        ncpus = 1;
    }

    need = (size_t) ncpus * val_size;

    if (m->sum_scratch == NULL || m->sum_scratch_size < need) {
        return -1;
    }

    buf = m->sum_scratch;
    memset(buf, 0, need);
    memset(out_sum, 0, val_size);

    if (bpf_map_lookup_elem(map_fd, key, buf) < 0) {
        return -1;
    }

    words = val_size / sizeof(uint64_t);

    for (cpu = 0; cpu < ncpus; cpu++) {
        uint64_t *src = (uint64_t *) (buf + (size_t) cpu * val_size);
        uint64_t *dst = out_sum;

        for (i = 0; i < words; i++) {
            dst[i] += src[i];
        }
    }

    return 0;
}


int
vg_metrics_read(struct vg_maps *m, struct vg_metrics *out)
{
    __u32 key = 0;

    return vg_sum_percpu(m, vg_maps_metrics_fd(m), &key, sizeof(*out), out);
}


static int
lpm_update(int fd, const struct vg_cidr *p, const void *val)
{
    if (p->family == AF_INET) {
        struct vg_lpm_v4 k = { .prefixlen = p->prefixlen };

        memcpy(k.data, p->addr, 4);
        return bpf_map_update_elem(fd, &k, val, BPF_ANY);
    }

    {
        struct vg_lpm_v6 k = { .prefixlen = p->prefixlen };

        memcpy(k.data, p->addr, 16);
        return bpf_map_update_elem(fd, &k, val, BPF_ANY);
    }
}


static int
lpm_delete(int fd, const struct vg_cidr *p)
{
    if (p->family == AF_INET) {
        struct vg_lpm_v4 k = { .prefixlen = p->prefixlen };

        memcpy(k.data, p->addr, 4);
        return bpf_map_delete_elem(fd, &k);
    }

    {
        struct vg_lpm_v6 k = { .prefixlen = p->prefixlen };

        memcpy(k.data, p->addr, 16);
        return bpf_map_delete_elem(fd, &k);
    }
}


int
vg_drop_add(struct vg_maps *m, const struct vg_cidr *p, uint32_t reason,
    uint32_t now)
{
    struct drop_entry e = { .reason = reason, .insert_time = now };
    int fd = p->family == AF_INET ? bpf_map__fd(m->skel->maps.drop_v4)
             : bpf_map__fd(m->skel->maps.drop_v6);

    return lpm_update(fd, p, &e);
}


int
vg_drop_del(struct vg_maps *m, const struct vg_cidr *p)
{
    int fd = p->family == AF_INET ? bpf_map__fd(m->skel->maps.drop_v4)
             : bpf_map__fd(m->skel->maps.drop_v6);

    return lpm_delete(fd, p);
}


static int
flush_lpm(int fd, int v6)
{
    int err;
    uint8_t key[sizeof(struct vg_lpm_v6)];
    uint8_t next[sizeof(struct vg_lpm_v6)];
    size_t ksz = v6 ? sizeof(struct vg_lpm_v6) : sizeof(struct vg_lpm_v4);

    memset(key, 0, sizeof(key));

    if (bpf_map_get_next_key(fd, NULL, next) < 0) {
        return 0;
    }

    memcpy(key, next, ksz);

    for ( ;; ) {
        err = bpf_map_get_next_key(fd, key, next);
        bpf_map_delete_elem(fd, key);

        if (err < 0) {
            break;
        }

        memcpy(key, next, ksz);
    }

    return 0;
}


int
vg_drop_flush(struct vg_maps *m)
{
    flush_lpm(bpf_map__fd(m->skel->maps.drop_v4), 0);
    flush_lpm(bpf_map__fd(m->skel->maps.drop_v6), 1);

    return 0;
}


/*
 * sw_flowd's table and config (Seawall proposals 0007, 0009), for every
 * object voidgate loads to bind: sw_flowd starts first. The table is not
 * versioned: maps of another layout are a sw_flowd built from another
 * sw_flowd.h than voidgate was, and are not bound. Without them, replies
 * to the host's flows are judged as any other until voidgate restarts.
 */
static void
flows_open(struct vg_maps *m)
{
    int tfd, cfd;
    __u32 len;
    struct bpf_map_info info, cinfo;

    tfd = bpf_obj_get(SF_PIN_ROOT "/" SF_PIN_OUTBOUND);
    cfd = bpf_obj_get(SF_PIN_ROOT "/" SF_PIN_CONFIG);

    if (tfd < 0 || cfd < 0) {
        sw_log_warn("no sw_flowd flow table under %s: replies to the host's "
                    "own flows are judged as any other until voidgate restarts "
                    "with it (start sw_flowd first)", SF_PIN_ROOT);
        goto none;
    }

    memset(&info, 0, sizeof(info));
    len = sizeof(info);

    if (bpf_map_get_info_by_fd(tfd, &info, &len) != 0) {
        goto refused;
    }

    memset(&cinfo, 0, sizeof(cinfo));
    len = sizeof(cinfo);

    if (bpf_map_get_info_by_fd(cfd, &cinfo, &len) != 0
        || info.type != BPF_MAP_TYPE_LRU_HASH
        || info.key_size != sizeof(struct sf_flow_key)
        || info.value_size != sizeof(struct sf_flow)
        || cinfo.type != BPF_MAP_TYPE_ARRAY
        || cinfo.key_size != sizeof(__u32)
        || cinfo.value_size != sizeof(struct sf_config))
    {
        goto refused;
    }

    m->flows_fd = tfd;
    m->flows_config_fd = cfd;
    m->flows_size = info.max_entries;
    m->flows_stats_fd = bpf_obj_get(SF_PIN_ROOT "/" SF_PIN_STATS);
    sw_log_info("reading sw_flowd's flow table (%u flows): replies to the "
                "host's own flows pass an armed gate", info.max_entries);

    return;

refused:

    sw_log_warn("sw_flowd's flow table under %s is not the layout this "
                "voidgate reads: not reading it", SF_PIN_ROOT);

none:

    if (tfd >= 0) {
        close(tfd);
    }

    if (cfd >= 0) {
        close(cfd);
    }
}


/* sw_flowd's counters, summed: 0, or -1 while its table is not in. */
int
vg_flows_stats(struct vg_maps *m, uint64_t *entries, uint64_t *evicted)
{
    __u32 key;
    struct sf_stats s;

    *entries = 0;
    *evicted = 0;

    if (m->flows_fd < 0 || m->flows_stats_fd < 0) {
        return -1;
    }

    for (key = SF_STATS_BPF; key <= SF_STATS_DAEMON; key++) {
        if (vg_sum_percpu(m, m->flows_stats_fd, &key, sizeof(s), &s) == 0) {
            *entries += s.entries;
            *evicted += s.evicted;
        }
    }

    return 0;
}


int
vg_populate_local(struct vg_maps *m, const struct vg_config *cfg)
{
    int i, fd4, fd6;
    uint8_t one = 1;

    fd4 = bpf_map__fd(m->skel->maps.local_v4);
    fd6 = bpf_map__fd(m->skel->maps.local_v6);
    flush_lpm(fd4, 0);
    flush_lpm(fd6, 1);

    for (i = 0; i < cfg->local_cidr_count; i++) {
        char buf[80];
        int fd = cfg->local_cidr[i].family == AF_INET ? fd4 : fd6;

        vg_cidr_to_str(&cfg->local_cidr[i], buf, sizeof(buf));

        if (lpm_update(fd, &cfg->local_cidr[i], &one) < 0) {
            sw_log_warn("failed to add local %s: %s", buf, strerror(errno));

        } else {
            sw_log_info("local network %s", buf);
        }
    }

    return 0;
}


int
vg_populate_allow(struct vg_maps *m, const struct vg_config *cfg)
{
    int i, fd4, fd6;
    uint8_t one = 1;

    fd4 = bpf_map__fd(m->skel->maps.allow_v4);
    fd6 = bpf_map__fd(m->skel->maps.allow_v6);
    flush_lpm(fd4, 0);
    flush_lpm(fd6, 1);

    for (i = 0; i < cfg->allow_cidr_count; i++) {
        int fd = cfg->allow_cidr[i].family == AF_INET ? fd4 : fd6;

        if (lpm_update(fd, &cfg->allow_cidr[i], &one) < 0) {
            sw_log_warn("failed to add allow prefix");
        }
    }

    return 0;
}
