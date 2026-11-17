
/* SPDX-License-Identifier: Apache-2.0 */

/* vg_parse_cidr and the config CIDR lists. A malformed prefix length must
 * be rejected, never truncated or read as /0: in allow_networks that would
 * allow-list everything.
 */

#include "config.h"
#include "ipaddr.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


static int g_fail;


static void
expect_cidr(const char *in, const char *want)
{
    struct vg_cidr p;
    char got[80];
    int rc = vg_parse_cidr(in, &p);

    if (rc == 0) {
        vg_cidr_to_str(&p, got, sizeof(got));
    }

    if ((want == NULL && rc == 0)
        || (want != NULL && (rc != 0 || strcmp(got, want) != 0)))
    {
        printf("FAIL parse '%s': want %s, got %s\n", in,
               want != NULL ? want : "reject", rc == 0 ? got : "reject");
        g_fail++;
    }
}


/* vg_parse_cidr_len: only the first n bytes of s count. */
static void
expect_cidr_len(const char *s, size_t n, const char *want)
{
    struct vg_cidr p;
    char got[80];
    int rc = vg_parse_cidr_len(s, n, &p);

    if (rc == 0) {
        vg_cidr_to_str(&p, got, sizeof(got));
    }

    if ((want == NULL && rc == 0)
        || (want != NULL && (rc != 0 || strcmp(got, want) != 0)))
    {
        printf("FAIL parse %zu bytes of '%s': want %s, got %s\n", n, s,
               want != NULL ? want : "reject", rc == 0 ? got : "reject");
        g_fail++;
    }
}


static int
load_config(const char *line, struct vg_config *cfg)
{
    char path[] = "/tmp/vg-cidr-XXXXXX";
    FILE *fp;
    int fd, rc;

    fd = mkstemp(path);

    if (fd < 0 || (fp = fdopen(fd, "w")) == NULL) {
        perror("mkstemp");
        exit(1);
    }

    fprintf(fp, "%s\n", line);
    fclose(fp);
    rc = vg_config_load(path, cfg);
    unlink(path);

    return rc;
}


static void
expect_config(const char *line, int want_rc)
{
    struct vg_config cfg;
    int rc = load_config(line, &cfg);

    if (rc != want_rc) {
        printf("FAIL config '%s': want %d, got %d\n", line, want_rc, rc);
        g_fail++;
    }
}


/* Repeated allow_networks / local_networks lines add up; the first one
 * replaces the built-in allow list.
 */
static void
expect_counts(const char *text, int want_allow, int want_local)
{
    struct vg_config cfg;
    int rc = load_config(text, &cfg);

    if (rc != 0 || cfg.allow_cidr_count != want_allow
        || cfg.local_cidr_count != want_local)
    {
        printf("FAIL config '%s': rc %d, allow %d (want %d), "
               "local %d (want %d)\n", text, rc, cfg.allow_cidr_count,
               want_allow, cfg.local_cidr_count, want_local);
        g_fail++;
    }
}


/* A CSV list far longer than any fixed line buffer must load whole: a line
 * split mid-token can turn 10.0.37.0/24 into 10.0.37.0/2, a /2 allow.
 */
static void
expect_long_list(int family, int n)
{
    static char line[16384];
    struct vg_config cfg;
    struct vg_cidr *list;
    size_t used;
    int i, rc, count, plen = family == AF_INET ? 24 : 48;

    used = (size_t) snprintf(line, sizeof(line), "%s =",
                             family == AF_INET ? "allow_networks"
                                               : "local_networks");

    for (i = 0; i < n; i++) {
        const char *sep = i ? ", " : " ";

        if (family == AF_INET) {
            used += (size_t) snprintf(line + used, sizeof(line) - used,
                                      "%s10.%d.%d.0/24", sep, i / 256, i % 256);

        } else {
            used += (size_t) snprintf(line + used, sizeof(line) - used,
                                      "%s2001:db8:%x::/48", sep, i);
        }
    }

    rc = load_config(line, &cfg);
    list = family == AF_INET ? cfg.allow_cidr : cfg.local_cidr;
    count = family == AF_INET ? cfg.allow_cidr_count : cfg.local_cidr_count;

    if (rc != 0 || count != n) {
        printf("FAIL %zu-byte %s list: rc %d, %d of %d entries\n", used,
               family == AF_INET ? "v4" : "v6", rc, count, n);
        g_fail++;
        return;
    }

    for (i = 0; i < count; i++) {
        if (list[i].prefixlen != plen) {
            printf("FAIL long list entry %d has prefix /%u\n", i,
                   list[i].prefixlen);
            g_fail++;
            return;
        }
    }
}


int
main(void)
{
    char long_cidr[256];

    expect_cidr("10.1.2.3/24", "10.1.2.0/24");
    expect_cidr("10.0.0.1", "10.0.0.1/32");
    expect_cidr("0.0.0.0/0", "0.0.0.0/0");
    expect_cidr("10.0.0.0/08", "10.0.0.0/8");
    expect_cidr("2001:db8::1/64", "2001:db8::/64");
    expect_cidr("2001:db8::1", "2001:db8::1/128");
    expect_cidr("::/0", "::/0");

    expect_cidr("10.0.0.0/33", NULL);
    expect_cidr("10.0.0.0/280", NULL);
    expect_cidr("10.0.0.0/4294967320", NULL);
    expect_cidr("2001:db8::/129", NULL);
    expect_cidr("2001:db8::/300", NULL);
    expect_cidr("10.0.0.1/", NULL);
    expect_cidr("10.0.0.1/abc", NULL);
    expect_cidr("10.0.0.1/-8", NULL);
    expect_cidr("10.0.0.1/+24", NULL);
    expect_cidr("10.0.0.1/ 24", NULL);
    expect_cidr("10.0.0.1/24x", NULL);
    expect_cidr("10.0.0.1/24/8", NULL);
    expect_cidr("/24", NULL);
    expect_cidr("", NULL);

    /* Longer than the parser's buffer: reject, do not parse a prefix. */
    memset(long_cidr, '1', sizeof(long_cidr) - 1);
    long_cidr[sizeof(long_cidr) - 1] = '\0';
    memcpy(long_cidr, "10.0.0.0/8", 10);
    expect_cidr(long_cidr, NULL);

    /* One word of a longer line, parsed in place (ctl "block <cidr> ..."). */
    expect_cidr_len("10.1.2.3/24 ttl=60", 11, "10.1.2.0/24");
    expect_cidr_len("2001:db8::1/64 ttl=60", 14, "2001:db8::/64");
    expect_cidr_len("10.0.0.1/24", 8, "10.0.0.1/32");
    expect_cidr_len("10.0.0.1/24", 9, NULL);    /* "10.0.0.1/" */
    expect_cidr_len("10.0.0.1 ttl=60", 0, NULL);
    expect_cidr_len("10.0.0.1\0/8", 11, NULL);  /* NUL inside n: reject */
    expect_cidr_len(long_cidr, sizeof(long_cidr) - 1, NULL);

    expect_config("allow_networks = 192.0.2.0/24, 2001:db8::/32", 0);
    expect_config("allow_networks = 10.0.0.0/", -1);
    expect_config("allow_networks = 10.0.0.0/abc", -1);
    expect_config("local_networks = 198.51.100.0/280", -1);

    expect_counts("wake_pps = 2000", 5, 0);
    expect_counts("allow_networks = 192.0.2.99/32", 1, 0);
    expect_counts("allow_networks = 169.254.169.254/32, 127.0.0.0/8\n"
                  "allow_networks = 192.0.2.99/32", 3, 0);
    expect_counts("allow_networks = 192.0.2.99/32\n"
                  "allow_networks =\n"
                  "allow_networks = 2001:db8::/32", 2, 0);
    expect_counts("local_networks = 198.51.100.10/32\n"
                  "local_networks = 2001:db8::10/128", 5, 2);

    /* VG_MAX_CIDR_LIST entries: about 4 KB (v4) and 5 KB (v6) per line. */
    expect_long_list(AF_INET, VG_MAX_CIDR_LIST);
    expect_long_list(AF_INET6, VG_MAX_CIDR_LIST);

    if (g_fail) {
        printf("%d cidr unit check(s) failed\n", g_fail);
        return 1;
    }

    puts("cidr unit tests passed");

    return 0;
}
