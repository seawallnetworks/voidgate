
/* SPDX-License-Identifier: Apache-2.0 */

#include "config.h"
#include "ctl_server.h"
#include "http.h"
#include "policy.h"
#include "log.h"
#include "maps.h"

#include <sw/netif.h>
#include <sw/notify.h>
#include <sw/sock.h>

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>


/* a control or metrics client gets this long to send and to read */
#define VG_SOCK_TIMEOUT_MS  200

/* the Makefile's, from CONFDIR */
#ifndef VG_CONF_PATH
#define VG_CONF_PATH  "/usr/local/seawall/etc/voidgate/voidgate.conf"
#endif


static void on_signal(int sig);
static void sock_unlink(void);
static long elapsed_ms(const struct timespec *a, const struct timespec *b);
static void usage(const char *argv0);
static void redirect_log(int fd);
static int daemon_start(int log_fd);
static int pid_lock(const char *path);
static void write_pidfile(int fd, const char *path);
static void daemon_stop(const char *path);

static volatile sig_atomic_t g_stop;

/* the process that removes the control socket if it exits early */
static pid_t vg_sock_owner;

static void
on_signal(int sig)
{
    (void) sig;
    g_stop = 1;
}


/* atexit(): a start that fails after listening leaves no socket behind */
static void
sock_unlink(void)
{
    if (vg_sock_owner == getpid()) {
        unlink(VG_SOCK_PATH);
    }
}


static long
elapsed_ms(const struct timespec *a, const struct timespec *b)
{
    return (a->tv_sec - b->tv_sec) * 1000L
           + (a->tv_nsec - b->tv_nsec) / 1000000L;
}


static void
usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s [-d] [-s stop] [-c config] [-i iface] [-g group]"
            " [-v|-vv]\n",
            argv0);
}


/* -d: the log file becomes stderr, so lines are formatted for a file */
static void
redirect_log(int fd)
{
    if (dup2(fd, STDERR_FILENO) < 0) {
        sw_log_fatal("redirect log: %s", strerror(errno));
    }

    if (fd != STDERR_FILENO) {
        close(fd);
    }

    sw_log_init("voidgate");
}


/* Return the readiness pipe in the daemon; the original parent exits. */
static int
daemon_start(int log_fd)
{
    int      fd, pipefd[2];
    pid_t    child, daemon_pid;
    ssize_t  n;

    if (pipe(pipefd) < 0) {
        sw_log_fatal("startup pipe: %s", strerror(errno));
    }

    fflush(NULL);
    child = fork();

    if (child < 0) {
        sw_log_fatal("fork: %s", strerror(errno));
    }

    if (child > 0) {
        /* the daemon's now: on its failed start it removes it itself */
        vg_sock_owner = 0;
        close(pipefd[1]);
        close(log_fd);

        do {
            n = read(pipefd[0], &daemon_pid, sizeof(daemon_pid));
        } while (n < 0 && errno == EINTR);

        close(pipefd[0]);

        if (n != sizeof(daemon_pid)) {
            sw_log_fatal("daemon startup failed; check the log file");
        }

        fprintf(stderr, "voidgate daemon started (pid %ld)\n",
                (long) daemon_pid);
        exit(0);
    }

    vg_sock_owner = getpid();
    close(pipefd[0]);
    redirect_log(log_fd);

    if (setsid() < 0) {
        sw_log_fatal("setsid: %s", strerror(errno));
    }

    fd = open("/dev/null", O_RDWR);

    if (fd < 0) {
        sw_log_fatal("open /dev/null: %s", strerror(errno));
    }

    if (dup2(fd, STDIN_FILENO) < 0 || dup2(fd, STDOUT_FILENO) < 0) {
        sw_log_fatal("redirect standard streams: %s", strerror(errno));
    }

    if (fd > STDERR_FILENO) {
        close(fd);
    }

    /* Keep cwd so relative config paths still work on reload. */
    return pipefd[1];
}


/* Hold an exclusive flock on the pid file for the daemon's lifetime: one
 * instance per pid file, released by the kernel even on a crash. Taken
 * before the fork, so the lock passes to the daemon with the fd.
 */
static int
pid_lock(const char *path)
{
    char buf[32];
    ssize_t n;
    int fd;

    fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0644);

    if (fd < 0) {
        sw_log_fatal("open pid file %s: %s", path, strerror(errno));
    }

    if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
        return fd;
    }

    if (errno != EWOULDBLOCK) {
        sw_log_fatal("lock pid file %s: %s", path, strerror(errno));
    }

    n = pread(fd, buf, sizeof(buf) - 1, 0);
    buf[n > 0 ? n : 0] = '\0';
    buf[strcspn(buf, "\n")] = '\0';
    sw_log_fatal("voidgate already running (pid %s, %s)",
                 buf[0] != '\0' ? buf : "?", path);
}


static void
write_pidfile(int fd, const char *path)
{
    char buf[32];
    int n;

    n = snprintf(buf, sizeof(buf), "%ld\n", (long) getpid());

    if (ftruncate(fd, 0) < 0 || pwrite(fd, buf, (size_t) n, 0) != n) {
        unlink(path);
        sw_log_fatal("write pid file %s: %s", path, strerror(errno));
    }
}


static void
daemon_stop(const char *path)
{
    char buf[32];
    struct timespec delay = { .tv_sec = 0, .tv_nsec = 50 * 1000 * 1000 };
    ssize_t n;
    long pid;
    int fd, i;

    fd = open(path, O_RDONLY);

    if (fd < 0) {
        sw_log_fatal("open pid file %s: %s", path, strerror(errno));
    }

    n = read(fd, buf, sizeof(buf) - 1);

    /* A live daemon holds LOCK_EX. If we can lock it, the pid inside is
     * stale and may belong to an unrelated process: never signal it.
     */
    if (flock(fd, LOCK_SH | LOCK_NB) == 0) {
        close(fd);
        unlink(path);
        sw_log_fatal("pid file %s is stale: voidgate is not running", path);
    }

    close(fd);

    if (n <= 0) {
        sw_log_fatal("read pid file %s: %s", path,
                     n < 0 ? strerror(errno) : "empty");
    }

    buf[n] = '\0';
    pid = strtol(buf, NULL, 10);

    if (pid <= 0) {
        sw_log_fatal("bad pid file %s", path);
    }

    if (kill((pid_t) pid, SIGTERM) < 0) {
        if (errno == ESRCH) {
            unlink(path);
        }

        sw_log_fatal("stop pid %ld: %s", pid, strerror(errno));
    }

    for (i = 0; i < 200; i++) {
        if (kill((pid_t) pid, 0) < 0) {
            if (errno == ESRCH) {
                unlink(path);
                return;
            }

            sw_log_fatal("stop pid %ld: %s", pid, strerror(errno));
        }

        nanosleep(&delay, NULL);
    }

    sw_log_fatal("stop pid %ld: timed out", pid);
}


int
main(int argc, char **argv)
{
    struct vg_config cfg;
    struct vg_maps maps;
    struct vg_ctrl ctrl;
    const char *cfg_path = VG_CONF_PATH;
    const char *iface_ov = NULL;
    const char *ctl_group = NULL;
    int opt, ctl_fd, http_fd = -1;
    int daemon_mode = 0, stop_mode = 0, log_fd = -1, ready_fd = -1;
    int result = 0;
    int pid_fd;
    struct sigaction sa;
    struct timespec last_tick;
    char err[256];

    sw_log_init("voidgate");

    while ((opt = getopt(argc, argv, "c:i:g:ds:hv")) != -1) {
        switch (opt) {
        case 'c':
            cfg_path = optarg;
            break;
        case 'i':
            iface_ov = optarg;
            break;
        case 'g':
            ctl_group = optarg;
            break;
        case 'v':
            if (vg_verbose < 2) {
                vg_verbose++;
            }

            sw_log_set_level(SW_LOG_DEBUG);
            break;
        case 'd':
            daemon_mode = 1;
            break;
        case 's':
            if (strcmp(optarg, "stop") != 0) {
                usage(argv[0]);
                return 1;
            }

            stop_mode = 1;
            break;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (vg_config_load(cfg_path, &cfg) < 0) {
        sw_log_fatal("failed to load config %s", cfg_path);
    }

    if (stop_mode) {
        daemon_stop(cfg.pid_file);
        return 0;
    }

    /* Before anything shared is touched: attach takes voidgate's programs
     * off the NIC and listen unlinks the socket path, so a second instance
     * would silently take over (and detach on exit) the first one's.
     */
    pid_fd = pid_lock(cfg.pid_file);

    switch (sw_sock_alive(VG_SOCK_PATH)) {
    case 0:
        break;
    case 1:
        unlink(cfg.pid_file);
        sw_log_fatal("another voidgate is already serving %s", VG_SOCK_PATH);
    default:
        unlink(cfg.pid_file);
        sw_log_fatal("can't tell whether a voidgate serves %s: %s",
                     VG_SOCK_PATH, strerror(errno));
    }

    /* Listening before the fork and the attach: a bad -g stops the start
     * with the NIC untouched, and reaches the caller's stderr with -d too.
     */
    ctl_fd = vg_ctl_server_listen(VG_SOCK_PATH, ctl_group, err, sizeof(err));

    if (ctl_fd < 0) {
        unlink(cfg.pid_file);
        sw_log_fatal("control socket %s", err);
    }

    vg_sock_owner = getpid();
    atexit(sock_unlink);

    if (iface_ov != NULL) {
        snprintf(cfg.interface, sizeof(cfg.interface), "%s", iface_ov);
    }

    switch (sw_netif_index(cfg.interface, err, sizeof(err))) {
    case 0:
        sw_log_fatal("unknown interface %s", cfg.interface);
    case -1:
        sw_log_fatal("%s", err);
    default:
        break;
    }

    if (vg_config_auto_local(&cfg) < 0) {
        sw_log_fatal("failed to read addresses on %s", cfg.interface);
    }

    /* In the foreground, as under the unit, the log is stderr: the
     * journal. log_file is for -d, which has no stderr to log to.
     */
    if (daemon_mode) {
        log_fd = open(cfg.log_file, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
                      0644);

        if (log_fd < 0) {
            sw_log_fatal("open log %s: %s", cfg.log_file, strerror(errno));
        }

        ready_fd = daemon_start(log_fd);
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    if (vg_maps_open(&maps, &cfg) < 0) {
        sw_log_fatal("BPF maps");
    }

    /* Attach loads the object, so the maps are filled after it: until
     * then cfg reads unarmed, and the program only counts and passes.
     */
    if (vg_attach(&maps, &cfg) < 0) {
        vg_maps_close(&maps);
        sw_log_fatal("attach failed");
    }

    if (vg_populate_allow(&maps, &cfg) < 0
        || vg_populate_local(&maps, &cfg) < 0)
    {
        vg_maps_close(&maps);
        sw_log_fatal("failed to populate allow/local maps");
    }

    if (vg_cfg_commit(&maps, 0, &cfg) < 0) {
        vg_maps_close(&maps);
        sw_log_fatal("failed to commit cfg map");
    }

    if (vg_ctrl_init(&ctrl, &cfg, &maps, cfg_path, iface_ov) < 0) {
        vg_maps_close(&maps);
        sw_log_fatal("control plane init failed");
    }

    sw_log_info("ctl socket %s", VG_SOCK_PATH);

    http_fd = vg_http_listen(cfg.metrics_port);

    if (http_fd >= 0) {
        sw_log_info("prometheus 127.0.0.1:%d/metrics", cfg.metrics_port);
    }

    vg_log_config(&cfg, vg_hook_name(&maps));
    sw_log_info("idle on %s, wake_pps=%llu wake_mbps=%llu", cfg.interface,
                (unsigned long long)cfg.wake_pps,
                (unsigned long long)cfg.wake_mbps);

    write_pidfile(pid_fd, cfg.pid_file);

    if (ready_fd >= 0) {
        pid_t daemon_pid = getpid();

        if (write(ready_fd, &daemon_pid, sizeof(daemon_pid))
            != sizeof(daemon_pid))
        {
            sw_log_warn("failed to report daemon readiness");
            g_stop = 1;
            result = 1;
        }

        close(ready_fd);
    }

    /* the socket listens and the program is attached: a unit ordered
     * after voidgate finds both
     */
    if (sw_notify_ready() != 0) {
        sw_log_warn("tell systemd voidgate is ready: %s", strerror(errno));
    }

    clock_gettime(CLOCK_MONOTONIC, &last_tick);
    while (!g_stop) {
        struct pollfd pfd[2];
        int nfds = 0, pr, wait_ms;
        struct timespec now;
        long elapsed;

        clock_gettime(CLOCK_MONOTONIC, &now);
        elapsed = elapsed_ms(&now, &last_tick);
        wait_ms = cfg.idle_poll_ms - (int) elapsed;

        if (wait_ms < 0) {
            wait_ms = 0;
        }

        pfd[nfds].fd = ctl_fd;
        pfd[nfds].events = POLLIN;
        nfds++;

        if (http_fd >= 0) {
            pfd[nfds].fd = http_fd;
            pfd[nfds].events = POLLIN;
            nfds++;
        }

        pr = poll(pfd, (nfds_t) nfds, wait_ms);

        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }

            break;
        }

        if (pr > 0) {
            int i;

            for (i = 0; i < nfds; i++) {
                int cfd;

                if (!(pfd[i].revents & POLLIN)) {
                    continue;
                }

                cfd = accept(pfd[i].fd, NULL, NULL);

                if (cfd < 0) {
                    continue;
                }

                sw_sock_timeouts(cfd, VG_SOCK_TIMEOUT_MS);

                if (pfd[i].fd == ctl_fd) {
                    vg_ctl_server_handle(&ctrl, cfd);

                } else {
                    vg_http_handle(&ctrl, cfd);
                }

                close(cfd);
            }
        }

        clock_gettime(CLOCK_MONOTONIC, &now);

        if (pr <= 0 || elapsed_ms(&now, &last_tick) >= cfg.idle_poll_ms) {
            vg_ctrl_tick(&ctrl);
            last_tick = now;
        }
    }

    vg_ctrl_disarm(&ctrl, "shutdown");
    vg_ctrl_free(&ctrl);
    vg_maps_close(&maps);

    close(ctl_fd);
    vg_sock_owner = 0;
    unlink(VG_SOCK_PATH);

    if (http_fd >= 0) {
        close(http_fd);
    }

    /* Last: once the lock is gone a new instance may start, and XDP and the
     * socket must already be released by then.
     */
    unlink(cfg.pid_file);
    close(pid_fd);

    sw_log_info("exit");

    return result;
}
