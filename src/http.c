
/* SPDX-License-Identifier: Apache-2.0 */

#include "http.h"
#include "maps.h"
#include "policy.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>


static void
format_prometheus(struct vg_ctrl *c, const struct vg_metrics *m, char *buf,
    size_t buflen)
{
    int n;
    uint64_t entries, evicted;

    n = snprintf(buf, buflen,
             "# TYPE voidgate_armed gauge\n"
             "voidgate_armed %d\n"
             "# TYPE voidgate_rx_packets_total counter\n"
             "voidgate_rx_packets_total %llu\n"
             "# TYPE voidgate_rx_bytes_total counter\n"
             "voidgate_rx_bytes_total %llu\n"
             "# TYPE voidgate_dropped_packets_total counter\n"
             "voidgate_dropped_packets_total %llu\n"
             "# TYPE voidgate_map_full_total counter\n"
             "voidgate_map_full_total %llu\n"
             "# TYPE voidgate_drop_prefixes gauge\n"
             "voidgate_drop_prefixes %d\n"
             "# TYPE voidgate_rx_pps gauge\n"
             "voidgate_rx_pps %.0f\n"
             "# TYPE voidgate_degraded gauge\n"
             "voidgate_degraded %d\n",
             c->state == VG_ACTIVE ? 1 : 0,
             (unsigned long long) m->rx_pkts,
             (unsigned long long) m->rx_bytes,
             (unsigned long long) m->dropped,
             (unsigned long long) m->map_full, c->drop_count, c->rx_pps,
             c->maps->degraded);

    if (n < 0 || (size_t) n >= buflen) {
        return;
    }

    /* sw_flowd's table: replies passed by it, and its own counters */
    n += snprintf(buf + n, buflen - (size_t) n,
                  "# TYPE voidgate_reply_passed_packets_total counter\n"
                  "voidgate_reply_passed_packets_total %llu\n"
                  "# TYPE voidgate_flow_table_attached gauge\n"
                  "voidgate_flow_table_attached %d\n",
                  (unsigned long long) m->reply_passed,
                  c->maps->flows_fd >= 0 ? 1 : 0);

    if (n < 0 || (size_t) n >= buflen
        || vg_flows_stats(c->maps, &entries, &evicted) != 0)
    {
        return;
    }

    snprintf(buf + n, buflen - (size_t) n,
             "# TYPE voidgate_flow_table_size gauge\n"
             "voidgate_flow_table_size %u\n"
             "# TYPE voidgate_flow_table_entries gauge\n"
             "voidgate_flow_table_entries %llu\n"
             "# TYPE voidgate_flow_table_evicted_total counter\n"
             "voidgate_flow_table_evicted_total %llu\n",
             c->maps->flows_size, (unsigned long long) entries,
             (unsigned long long) evicted);
}


int
vg_http_listen(int port)
{
    struct sockaddr_in addr;
    int fd, one = 1;

    if (port <= 0) {
        return -1;
    }

    fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);

    if (fd < 0) {
        return -1;
    }

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t) port);

    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    if (listen(fd, 8) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}


void
vg_http_handle(struct vg_ctrl *ctrl, int fd)
{
    struct vg_metrics m;
    char req[512], body[4096], resp[4608];
    ssize_t n;

    n = read(fd, req, sizeof(req) - 1);

    if (n <= 0) {
        return;
    }

    req[n] = 0;

    if (strncmp(req, "GET ", 4) != 0 || strstr(req, "/metrics") == NULL) {
        const char *nf = "HTTP/1.1 404 Not Found\r\n"
                         "Content-Length: 0\r\nConnection: close\r\n\r\n";
        ssize_t wr = write(fd, nf, strlen(nf));

        (void) wr;
        return;
    }

    memset(&m, 0, sizeof(m));
    vg_metrics_read(ctrl->maps, &m);
    format_prometheus(ctrl, &m, body, sizeof(body));
    snprintf(resp, sizeof(resp),
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: text/plain; version=0.0.4\r\n"
             "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
             strlen(body), body);
    {
        ssize_t wr = write(fd, resp, strlen(resp));

        (void) wr;
    }
}
