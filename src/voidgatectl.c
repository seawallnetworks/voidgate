
/* SPDX-License-Identifier: Apache-2.0 */

#include "bpf/voidgate.h"

#include <sw/sock.h>
#include <sw/time.h>

#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>


/* bounds connect() too: a voidgate that never accepts or answers */
#define VG_CTL_TIMEOUT_MS  5000

#define VG_CTL_REPLY_SIZE  4096
#define VG_CTL_CELL        32
#define VG_CTL_COLS        16
#define VG_CTL_COUNTERS    8
#define VG_CTL_MAX_SEC     3600
#define VG_CTL_PAGE_SIZE   65536
#define VG_CTL_STATS_COLS  9
#define VG_CTL_STATS_WIDTH 6


typedef enum {
    vg_key_u64 = 0,
    vg_key_double,
    vg_key_int,
    vg_key_str
} vg_key_e;


typedef struct {
    uint64_t    rx_pkts;
    uint64_t    rx_bytes;
    uint64_t    passed;
    uint64_t    dropped;
    uint64_t    non_ip;
    uint64_t    map_full;
    uint64_t    parse_err;
    uint64_t    reply_passed;
    double      rx_pps;
    double      rx_bps;
    int         blocked;
    int         counters;
    long long   at;
    char        state[16];
    char        critical[VG_CTL_REPLY_SIZE];
} vg_stats_t;


typedef struct {
    uint64_t    id;
    long long   inserted;
    long long   expires;
    char        cidr[64];
    char        reason[16];
} vg_block_t;


typedef struct {
    const char  *name;
    vg_key_e     type;
    size_t       offset;
    size_t       size;
} vg_stats_key_t;


static void usage(void);
static int raw_command(const char *path, int argc, char **argv);
static int request(const char *path, const char *cmd, char *reply,
    size_t size);
static int stats_read(const char *path, vg_stats_t *s);
static void stats_parse(char *reply, vg_stats_t *s);
static void stats_word(char *word, vg_stats_t *s);
static int stats_once(const char *path);
static int status_table(const char *path);
static int blocks_list(const char *path);
static int blocks_page(char *reply, vg_block_t **v, size_t *n, size_t *cap,
    char *epoch, uint64_t *next);
static void blocks_line(char *line, vg_block_t *b);
static void local_time(char *out, size_t size, long long t);
static int stats_watch(const char *path, int interval, long count);
static void stats_row(const char *when, const vg_stats_t *a,
    const vg_stats_t *b, int average);
static void stats_cells(char (*val)[VG_CTL_CELL], const vg_stats_t *s,
    int totals, double pps, double bps, double drop);
static void stats_print(const char *when, char (*val)[VG_CTL_CELL],
    uint64_t map_full, uint64_t parse_err);
static int stats_reset(const vg_stats_t *a, const vg_stats_t *b);
static void table(const char **head, char (*val)[VG_CTL_CELL], int n);
static void human(char *out, size_t size, double v);
static double percent(uint64_t part, uint64_t whole);
static int parse_num(const char *s, long max, long *out);
static void on_signal(int signo);


#define vg_stats_key(name, type)                                         \
    { #name, type, offsetof(vg_stats_t, name),                           \
      sizeof(((vg_stats_t *) 0)->name) }

static const vg_stats_key_t  vg_stats_keys[] = {
    vg_stats_key(rx_pkts, vg_key_u64),
    vg_stats_key(rx_bytes, vg_key_u64),
    vg_stats_key(passed, vg_key_u64),
    vg_stats_key(dropped, vg_key_u64),
    vg_stats_key(non_ip, vg_key_u64),
    vg_stats_key(map_full, vg_key_u64),
    vg_stats_key(parse_err, vg_key_u64),
    vg_stats_key(reply_passed, vg_key_u64),
    vg_stats_key(rx_pps, vg_key_double),
    vg_stats_key(rx_bps, vg_key_double),
    vg_stats_key(blocked, vg_key_int),
    vg_stats_key(state, vg_key_str)
};

#define VG_STATS_NKEYS  (sizeof(vg_stats_keys) / sizeof(vg_stats_keys[0]))

/*
 * stats's columns, alone and with an interval. non_ip and reply_passed
 * are normal traffic, only in -r stats; map_full and parse_err, errors,
 * follow the row when not 0.
 */
static const char  *vg_stats_head[VG_CTL_STATS_COLS] = {
    "state", "blocked", "rx_pkts", "rx_pps", "rx_bytes", "rx_bps", "passed",
    "dropped", "drop%"
};

static volatile sig_atomic_t  vg_stop;


int
main(int argc, char **argv)
{
    int          i, raw = 0;
    long         interval = 0, count = 0;
    const char  *path = VG_SOCK_PATH;

    /* -s: another socket, such as the read-only one; -r: the raw answer */
    for (i = 1; i < argc && argv[i][0] == '-'; i++) {
        if (strcmp(argv[i], "-r") == 0) {
            raw = 1;

        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            path = argv[++i];

        } else {
            usage();
            return 1;
        }
    }

    if (i >= argc) {
        usage();
        return 1;
    }

    if (!raw && argc - i == 1 && strcmp(argv[i], "status") == 0) {
        return status_table(path);
    }

    /* blocks: every page, as a table; "blocks after <id>" one page, raw */
    if (!raw && argc - i == 1 && strcmp(argv[i], "blocks") == 0) {
        return blocks_list(path);
    }

    if (raw || strcmp(argv[i], "stats") != 0) {
        return raw_command(path, argc - i, argv + i);
    }

    /* stats [<interval> [<count>]], as mpstat */
    if (argc - i > 3
        || (argc - i > 1
            && parse_num(argv[i + 1], VG_CTL_MAX_SEC, &interval) != 0)
        || (argc - i > 2
            && parse_num(argv[i + 2], 1000000000L, &count) != 0))
    {
        usage();
        return 1;
    }

    if (interval == 0) {
        return stats_once(path);
    }

    return stats_watch(path, (int) interval, count);
}


static void
usage(void)
{
    fprintf(stderr, "usage: voidgatectl [-r] [-s socket] status|"
            "stats [<interval> [<count>]]|\n"
            "       blocks [after <id>]|block <cidr> [ttl=<sec>]|"
            "unblock <cidr>|\n"
            "       arm|disarm|reload|feed [<epoch> <seq>]\n"
            "  -r  the daemon's answer as is (status, stats, blocks: "
            "key=value)\n"
            "  -s  default " VG_SOCK_PATH "; read-only: "
            VG_MONITOR_SOCK_PATH "\n");
}


/* sends the words as one command and copies the answer to stdout */
static int
raw_command(const char *path, int argc, char **argv)
{
    int      fd, i, failed = 0, replied = 0;
    ssize_t  n;
    char     cmd[256], buf[8192], err[256];

    cmd[0] = 0;

    for (i = 0; i < argc; i++) {
        if (i > 0) {
            strncat(cmd, " ", sizeof(cmd) - strlen(cmd) - 1);
        }

        strncat(cmd, argv[i], sizeof(cmd) - strlen(cmd) - 1);
    }

    strncat(cmd, "\n", sizeof(cmd) - strlen(cmd) - 1);

    fd = sw_sock_connect_unix(path, VG_CTL_TIMEOUT_MS, err, sizeof(err));

    if (fd < 0) {
        fprintf(stderr, "voidgatectl: %s\n", err);
        return 1;
    }

    if (sw_sock_send_all(fd, cmd, strlen(cmd)) < 0) {
        perror("voidgatectl: send");
        close(fd);
        return 1;
    }

    shutdown(fd, SHUT_WR);

    while ((n = read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = 0;

        /* Scripts need a refused command to fail. */
        if (!replied && strncmp(buf, "error", 5) == 0) {
            failed = 1;
        }

        replied = 1;
        fputs(buf, stdout);
    }

    close(fd);

    return failed || !replied;
}


/* one command, its whole answer in reply; -1 with a message on stderr */
static int
request(const char *path, const char *cmd, char *reply, size_t size)
{
    int      fd;
    size_t   len = 0;
    ssize_t  n;
    char     err[256];

    fd = sw_sock_connect_unix(path, VG_CTL_TIMEOUT_MS, err, sizeof(err));

    if (fd < 0) {
        fprintf(stderr, "voidgatectl: %s\n", err);
        return -1;
    }

    if (sw_sock_send_all(fd, cmd, strlen(cmd)) < 0) {
        perror("voidgatectl: send");
        close(fd);
        return -1;
    }

    shutdown(fd, SHUT_WR);

    while (len < size - 1
           && (n = read(fd, reply + len, size - 1 - len)) > 0)
    {
        len += (size_t) n;
    }

    close(fd);
    reply[len] = 0;

    if (len == 0) {
        fprintf(stderr, "voidgatectl: no answer\n");
        return -1;
    }

    return 0;
}


/*
 * The gate's state from status, then the counters from stats. A key
 * status doesn't give stays unknown (-1, or empty) and shows as "-":
 * a voidgate of another version is seen, not shown as 0. Every counter
 * must be there.
 */
static int
stats_read(const char *path, vg_stats_t *s)
{
    int          i;
    char         reply[VG_CTL_REPLY_SIZE];
    const char  *cmd[] = { "status\n", "stats\n" };

    memset(s, 0, sizeof(*s));
    s->rx_pps = -1;
    s->rx_bps = -1;
    s->blocked = -1;

    for (i = 0; i < 2; i++) {
        if (request(path, cmd[i], reply, sizeof(reply)) != 0) {
            return -1;
        }

        if (strncmp(reply, "error", 5) == 0) {
            fputs(reply, stderr);
            return -1;
        }

        stats_parse(reply, s);
    }

    if (s->counters != VG_CTL_COUNTERS) {
        fprintf(stderr, "voidgatectl: unexpected answer to stats\n");
        return -1;
    }

    s->at = sw_now_msec();

    return 0;
}


/*
 * key=value words; a line without "=" (the CRITICAL line) is kept whole.
 * Unknown keys are skipped.
 */
static void
stats_parse(char *reply, vg_stats_t *s)
{
    char  *line, *next, *word, *save;

    for (line = reply; line != NULL; line = next) {
        next = strchr(line, '\n');

        if (next != NULL) {
            *next++ = 0;
        }

        if (*line == 0) {
            continue;
        }

        if (strchr(line, '=') == NULL) {
            if (s->critical[0] == 0) {
                snprintf(s->critical, sizeof(s->critical), "%s", line);
            }

            continue;
        }

        for (word = strtok_r(line, " ", &save);
             word != NULL;
             word = strtok_r(NULL, " ", &save))
        {
            stats_word(word, s);
        }
    }
}


static void
stats_word(char *word, vg_stats_t *s)
{
    char                  *eq, *field;
    size_t                 k;
    const vg_stats_key_t  *key;

    eq = strchr(word, '=');

    if (eq == NULL) {
        return;
    }

    *eq++ = 0;

    for (k = 0; k < VG_STATS_NKEYS; k++) {
        key = &vg_stats_keys[k];

        if (strcmp(word, key->name) == 0) {
            break;
        }
    }

    if (k == VG_STATS_NKEYS) {
        return;
    }

    field = (char *) s + key->offset;

    switch (key->type) {
    case vg_key_u64:
        *(uint64_t *) field = strtoull(eq, NULL, 10);
        s->counters++;
        break;

    case vg_key_double:
        *(double *) field = strtod(eq, NULL);
        break;

    case vg_key_int:
        *(int *) field = atoi(eq);
        break;

    default:
        snprintf(field, key->size, "%s", eq);
        break;
    }
}


/*
 * One reading, one row: the state, then each total next to its rate, and
 * drop% next to dropped.
 */
static int
stats_once(const char *path)
{
    time_t      t;
    struct tm   tm;
    vg_stats_t  s;
    char        when[16];
    char        val[VG_CTL_STATS_COLS][VG_CTL_CELL];

    if (stats_read(path, &s) != 0) {
        return 1;
    }

    t = time(NULL);
    localtime_r(&t, &tm);
    strftime(when, sizeof(when), "%H:%M:%S", &tm);

    if (s.critical[0] != 0) {
        printf("%s\n\n", s.critical);
    }

    stats_cells(val, &s, 1, s.rx_pps, s.rx_bps,
                percent(s.dropped, s.rx_pkts));
    stats_print("", NULL, 0, 0);
    stats_print(when, val, s.map_full, s.parse_err);

    return 0;
}


/*
 * status as one row: a column for each key=value the daemon gives, in
 * its order, so a new key needs no change here; but the rates, rx_pps,
 * rx_bps, wake_rx_pps and wake_rx_bps, which are traffic. A line
 * without "=" (CRITICAL) comes first, as is.
 */
static int
status_table(const char *path)
{
    int          n = 0;
    char        *line, *next, *word, *save, *eq;
    const char  *head[VG_CTL_COLS];
    char         val[VG_CTL_COLS][VG_CTL_CELL];
    char         reply[VG_CTL_REPLY_SIZE];

    if (request(path, "status\n", reply, sizeof(reply)) != 0) {
        return 1;
    }

    if (strncmp(reply, "error", 5) == 0) {
        fputs(reply, stderr);
        return 1;
    }

    for (line = reply; line != NULL; line = next) {
        next = strchr(line, '\n');

        if (next != NULL) {
            *next++ = 0;
        }

        if (*line == 0) {
            continue;
        }

        if (strchr(line, '=') == NULL) {
            printf("%s\n\n", line);
            continue;
        }

        for (word = strtok_r(line, " ", &save);
             word != NULL && n < VG_CTL_COLS;
             word = strtok_r(NULL, " ", &save))
        {
            eq = strchr(word, '=');

            if (eq == NULL) {
                continue;
            }

            *eq++ = 0;

            /* the rates are traffic: voidgatectl stats shows them */
            if (strcmp(word, "rx_pps") == 0 || strcmp(word, "rx_bps") == 0
                || strcmp(word, "wake_rx_pps") == 0
                || strcmp(word, "wake_rx_bps") == 0)
            {
                continue;
            }

            head[n] = word;
            snprintf(val[n], VG_CTL_CELL, "%s", eq);
            n++;
        }
    }

    if (n == 0) {
        fprintf(stderr, "voidgatectl: unexpected answer to status\n");
        return 1;
    }

    table(head, val, n);

    return 0;
}

/*
 * Every listed block, oldest first: "blocks", then "blocks after <next>"
 * until "next=end", as one table. Every page must be of the first one's
 * epoch: a voidgate restarted in between counts ids from 1 again.
 * expires: a timed block's; a manual one never; policy and aggregate
 * ones ban_time after since, which the daemon doesn't say (expires=0).
 */
static int
blocks_list(const char *path)
{
    int          rc = 1, wid = 2, wcidr = 4, wreason = 6, w;
    char        *reply;
    size_t       i, n = 0, cap = 0;
    uint64_t     next = 0, after = 0;
    vg_block_t  *v = NULL;
    char         cmd[64], since[32], until[32], epoch[32], first[32];

    first[0] = 0;
    reply = malloc(VG_CTL_PAGE_SIZE);

    if (reply == NULL) {
        fprintf(stderr, "voidgatectl: out of memory\n");
        return 1;
    }

    snprintf(cmd, sizeof(cmd), "blocks\n");

    for ( ;; ) {
        if (request(path, cmd, reply, VG_CTL_PAGE_SIZE) != 0) {
            goto done;
        }

        if (strncmp(reply, "error", 5) == 0) {
            fputs(reply, stderr);
            goto done;
        }

        if (blocks_page(reply, &v, &n, &cap, epoch, &next) != 0) {
            fprintf(stderr, "voidgatectl: unexpected answer to blocks\n");
            goto done;
        }

        if (first[0] == 0) {
            snprintf(first, sizeof(first), "%s", epoch);

        } else if (strcmp(first, epoch) != 0) {
            fprintf(stderr, "voidgatectl: voidgate restarted while the "
                    "blocks were read; run it again\n");
            goto done;
        }

        if (next == 0) {
            break;
        }

        /* ids only grow: a next not past the last one would never end */
        if (next <= after) {
            fprintf(stderr, "voidgatectl: blocks: next=%llu after %llu\n",
                    (unsigned long long) next, (unsigned long long) after);
            goto done;
        }

        after = next;
        snprintf(cmd, sizeof(cmd), "blocks after %llu\n",
                 (unsigned long long) after);
    }

    if (n == 0) {
        printf("(none)\n");
        rc = 0;
        goto done;
    }

    for (i = 0; i < n; i++) {
        w = snprintf(NULL, 0, "%llu", (unsigned long long) v[i].id);
        wid = w > wid ? w : wid;
        w = (int) strlen(v[i].cidr);
        wcidr = w > wcidr ? w : wcidr;
        w = (int) strlen(v[i].reason);
        wreason = w > wreason ? w : wreason;
    }

    printf("%*s  %-*s  %-*s  %-19s  %s\n", wid, "id", wcidr, "cidr",
           wreason, "reason", "since", "expires");

    for (i = 0; i < n; i++) {
        local_time(since, sizeof(since), v[i].inserted);

        if (v[i].expires != 0) {
            local_time(until, sizeof(until), v[i].expires);

        } else if (strcmp(v[i].reason, "manual") == 0) {
            snprintf(until, sizeof(until), "never");

        } else {
            snprintf(until, sizeof(until), "ban_time");
        }

        printf("%*llu  %-*s  %-*s  %-19s  %s\n", wid,
               (unsigned long long) v[i].id, wcidr, v[i].cidr, wreason,
               v[i].reason, since, until);
    }

    rc = 0;

done:

    free(v);
    free(reply);

    return rc;
}


/*
 * One page: "epoch=<16 hex> seq=N n=K next=<id>|end", then a line per
 * block. next is 0 for "end".
 */
static int
blocks_page(char *reply, vg_block_t **v, size_t *n, size_t *cap,
    char *epoch, uint64_t *next)
{
    char        *line, *eol, *p;
    size_t       ncap, len;
    vg_block_t  *nv;

    eol = strchr(reply, '\n');
    p = strstr(reply, " next=");

    if (eol == NULL || p == NULL || p > eol
        || strncmp(reply, "epoch=", 6) != 0)
    {
        return -1;
    }

    *eol = 0;
    len = strcspn(reply + 6, " ");

    if (len == 0 || len >= 32) {
        return -1;
    }

    memcpy(epoch, reply + 6, len);
    epoch[len] = 0;
    p += sizeof(" next=") - 1;
    *next = strcmp(p, "end") == 0 ? 0 : strtoull(p, NULL, 10);

    if (*next == 0 && strcmp(p, "end") != 0) {
        return -1;
    }

    for (line = eol + 1; *line != 0; line = eol + 1) {
        eol = strchr(line, '\n');

        if (eol == NULL) {
            return -1;
        }

        *eol = 0;

        if (*n == *cap) {
            ncap = *cap ? *cap * 2 : 256;
            nv = realloc(*v, ncap * sizeof(vg_block_t));

            if (nv == NULL) {
                return -1;
            }

            *v = nv;
            *cap = ncap;
        }

        blocks_line(line, &(*v)[*n]);

        if ((*v)[*n].cidr[0] == 0) {
            return -1;
        }

        (*n)++;
    }

    return 0;
}


/* "id=N cidr=C reason=R inserted=<Unix s> expires=<Unix s, 0 if none>" */
static void
blocks_line(char *line, vg_block_t *b)
{
    char  *word, *save, *eq;

    memset(b, 0, sizeof(*b));

    for (word = strtok_r(line, " ", &save);
         word != NULL;
         word = strtok_r(NULL, " ", &save))
    {
        eq = strchr(word, '=');

        if (eq == NULL) {
            continue;
        }

        *eq++ = 0;

        if (strcmp(word, "id") == 0) {
            b->id = strtoull(eq, NULL, 10);

        } else if (strcmp(word, "cidr") == 0) {
            snprintf(b->cidr, sizeof(b->cidr), "%s", eq);

        } else if (strcmp(word, "reason") == 0) {
            snprintf(b->reason, sizeof(b->reason), "%s", eq);

        } else if (strcmp(word, "inserted") == 0) {
            b->inserted = strtoll(eq, NULL, 10);

        } else if (strcmp(word, "expires") == 0) {
            b->expires = strtoll(eq, NULL, 10);
        }
    }
}


static void
local_time(char *out, size_t size, long long t)
{
    time_t     tt = (time_t) t;
    struct tm  tm;

    localtime_r(&tt, &tm);
    strftime(out, size, "%Y-%m-%d %H:%M:%S", &tm);
}


/*
 * A row every interval seconds, from the counters' increase over it, then
 * an Average row over the whole run: after count rows, or on Ctrl-C.
 */
static int
stats_watch(const char *path, int interval, long count)
{
    int                rc = 0;
    long               rows = 0, averaged = 0;
    time_t             t;
    struct tm          tm;
    vg_stats_t         first, prev, cur;
    struct timespec    next;
    struct sigaction   sa;
    char               when[16];

    /* no SA_RESTART: Ctrl-C ends the sleep at once */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    if (stats_read(path, &first) != 0) {
        return 1;
    }

    if (first.critical[0] != 0) {
        printf("%s\n\n", first.critical);
    }

    /* stats's columns, after the time */
    stats_print("", NULL, 0, 0);
    fflush(stdout);

    prev = first;
    clock_gettime(CLOCK_MONOTONIC, &next);

    while (!vg_stop && (count == 0 || rows < count)) {
        next.tv_sec += interval;

        while (!vg_stop
               && clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next,
                                  NULL) == EINTR)
        {
            /* void */
        }

        if (vg_stop) {
            break;
        }

        if (stats_read(path, &cur) != 0) {
            rc = !vg_stop;
            break;
        }

        t = time(NULL);
        localtime_r(&t, &tm);
        strftime(when, sizeof(when), "%H:%M:%S", &tm);

        if (stats_reset(&prev, &cur)) {
            /* voidgate restarted: start over from its new counters */
            printf("%-8s  voidgate restarted, counters reset\n", when);
            fflush(stdout);
            first = prev = cur;
            averaged = 0;
            rows++;
            continue;
        }

        stats_row(when, &prev, &cur, 0);
        prev = cur;
        averaged++;
        rows++;
    }

    /* Ctrl-C: the rows so far, no Average */
    if (averaged > 0 && !vg_stop) {
        stats_row("Average:", &first, &prev, 1);
    }

    return rc;
}


/*
 * stats's row at b, but rx_pps, rx_bps and drop% over the interval from
 * a, and the map_full and parse_err of it. The Average row has only the
 * three rates.
 */
static void
stats_row(const char *when, const vg_stats_t *a, const vg_stats_t *b,
    int average)
{
    double    dt;
    uint64_t  pkts;
    char      val[VG_CTL_STATS_COLS][VG_CTL_CELL];

    dt = (double) (b->at - a->at) / 1000.0;

    if (dt <= 0) {
        dt = 1;
    }

    pkts = b->rx_pkts - a->rx_pkts;

    stats_cells(val, b, !average, (double) pkts / dt,
                (double) (b->rx_bytes - a->rx_bytes) * 8 / dt,
                percent(b->dropped - a->dropped, pkts));
    /* the errors of this interval: one long ago would repeat on every row */
    if (average) {
        stats_print(when, val, 0, 0);

    } else {
        stats_print(when, val, b->map_full - a->map_full,
                    b->parse_err - a->parse_err);
    }

    fflush(stdout);
}


/* stats's cells: s's state and totals, unless !totals ("-"), and the rates */
static void
stats_cells(char (*val)[VG_CTL_CELL], const vg_stats_t *s, int totals,
    double pps, double bps, double drop)
{
    snprintf(val[0], VG_CTL_CELL, "%s",
             totals && s->state[0] != 0 ? s->state : "-");

    if (!totals || s->blocked < 0) {
        snprintf(val[1], VG_CTL_CELL, "-");

    } else {
        snprintf(val[1], VG_CTL_CELL, "%d", s->blocked);
    }

#define vg_total(v)  (totals ? (double) (v) : -1)

    human(val[2], VG_CTL_CELL, vg_total(s->rx_pkts));
    human(val[3], VG_CTL_CELL, pps);
    human(val[4], VG_CTL_CELL, vg_total(s->rx_bytes));
    human(val[5], VG_CTL_CELL, bps);
    human(val[6], VG_CTL_CELL, vg_total(s->passed));
    human(val[7], VG_CTL_CELL, vg_total(s->dropped));
    snprintf(val[8], VG_CTL_CELL, "%.2f", drop);

#undef vg_total
}


/*
 * One line of stats's columns after when, the time; the header when val
 * is NULL. Each column as wide as its header, at least
 * VG_CTL_STATS_WIDTH: rows printed one at a time line up. Then
 * map_full and parse_err, when not 0.
 */
static void
stats_print(const char *when, char (*val)[VG_CTL_CELL], uint64_t map_full,
    uint64_t parse_err)
{
    int     i;
    size_t  w;

    printf("%-8s  ", when);

    for (i = 0; i < VG_CTL_STATS_COLS; i++) {
        w = strlen(vg_stats_head[i]);

        if (w < VG_CTL_STATS_WIDTH) {
            w = VG_CTL_STATS_WIDTH;
        }

        printf("%s%*s", i ? "  " : "", (int) w,
               val != NULL ? val[i] : vg_stats_head[i]);
    }

    if (map_full != 0) {
        printf("  map_full=%llu", (unsigned long long) map_full);
    }

    if (parse_err != 0) {
        printf("  parse_err=%llu", (unsigned long long) parse_err);
    }

    printf("\n");
}


/* a counter went down: a new daemon, counting from zero */
static int
stats_reset(const vg_stats_t *a, const vg_stats_t *b)
{
    return b->rx_pkts < a->rx_pkts || b->rx_bytes < a->rx_bytes
           || b->passed < a->passed || b->dropped < a->dropped
           || b->map_full < a->map_full || b->parse_err < a->parse_err;
}


/* a header row and a value row, each column as wide as its widest cell */
static void
table(const char **head, char (*val)[VG_CTL_CELL], int n)
{
    int     i, w[VG_CTL_COLS];
    size_t  hl, vl;

    for (i = 0; i < n; i++) {
        hl = strlen(head[i]);
        vl = strlen(val[i]);
        w[i] = (int) (hl > vl ? hl : vl);
    }

    for (i = 0; i < n; i++) {
        printf("%s%*s", i ? "  " : "", w[i], head[i]);
    }

    printf("\n");

    for (i = 0; i < n; i++) {
        printf("%s%*s", i ? "  " : "", w[i], val[i]);
    }

    printf("\n");
}


/* exact below 100000, else three digits and k, M, G, T or P; "-" below 0,
 * unknown */
static void
human(char *out, size_t size, double v)
{
    int          i = 0;
    const char  *unit = "kMGTP";

    if (v < 0) {
        snprintf(out, size, "-");
        return;
    }

    if (v < 99999.5) {
        snprintf(out, size, "%.0f", v);
        return;
    }

    v /= 1000;

    while (v >= 999.5 && unit[i + 1] != 0) {
        v /= 1000;
        i++;
    }

    if (v < 9.995) {
        snprintf(out, size, "%.2f%c", v, unit[i]);

    } else if (v < 99.95) {
        snprintf(out, size, "%.1f%c", v, unit[i]);

    } else {
        snprintf(out, size, "%.0f%c", v, unit[i]);
    }
}


static double
percent(uint64_t part, uint64_t whole)
{
    return whole == 0 ? 0 : (double) part * 100 / (double) whole;
}


/* a whole number from 1 to max */
static int
parse_num(const char *s, long max, long *out)
{
    long   v;
    char  *end;

    errno = 0;
    v = strtol(s, &end, 10);

    if (errno != 0 || end == s || *end != 0 || v < 1 || v > max) {
        return -1;
    }

    *out = v;

    return 0;
}


static void
on_signal(int signo)
{
    vg_stop = 1;
}
