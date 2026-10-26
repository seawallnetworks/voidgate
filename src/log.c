
/* SPDX-License-Identifier: Apache-2.0 */

#include "config.h"
#include "ipaddr.h"
#include "log.h"


int vg_verbose;


static void
log_config_cidrs(const char *key, const struct vg_cidr *cidrs, int count)
{
    char buf[80];
    int i;

    fprintf(stderr, "  ├─ %s = ", key);

    for (i = 0; i < count; i++) {
        vg_cidr_to_str(&cidrs[i], buf, sizeof(buf));
        fprintf(stderr, "%s%s", i == 0 ? "" : ", ", buf);
    }

    fputc('\n', stderr);
}


static void
log_config_ports(const struct vg_config *cfg)
{
    int i;

    fputs("  ├─ allow_ports = ", stderr);

    for (i = 0; i < cfg->allow_port_count; i++) {
        fprintf(stderr, "%s%u", i == 0 ? "" : ", ", cfg->allow_ports[i]);
    }

    fputc('\n', stderr);
}


void
vg_log_config_at(const char *file, int line,
    const struct vg_config *cfg, const char *hook)
{
    if (vg_verbose < 1) {
        return;
    }

    vg_log_at(file, line, "attached at %s", hook);
    vg_log_at(file, line, "active configuration");
    fprintf(stderr, "  ├─ interface = %s\n", cfg->interface);
    fprintf(stderr, "  ├─ xdp_mode = %s\n", cfg->xdp_mode);
    fprintf(stderr, "  ├─ hook = %s\n", cfg->hook);
    fprintf(stderr, "  ├─ wake_pps = %llu\n",
            (unsigned long long) cfg->wake_pps);
    fprintf(stderr, "  ├─ wake_mbps = %llu\n",
            (unsigned long long) cfg->wake_mbps);
    fprintf(stderr, "  ├─ idle_poll_ms = %d\n", cfg->idle_poll_ms);
    fprintf(stderr, "  ├─ clear_seconds = %d\n", cfg->clear_seconds);
    fprintf(stderr, "  ├─ threshold_pps = %llu\n",
            (unsigned long long) cfg->threshold_pps);
    fprintf(stderr, "  ├─ threshold_mbps = %llu\n",
            (unsigned long long) cfg->threshold_mbps);
    fprintf(stderr, "  ├─ ban_time = %d\n", cfg->ban_time);
    fprintf(stderr, "  ├─ aggregate_k = %d\n", cfg->aggregate_k);
    log_config_cidrs("local_networks", cfg->local_cidr,
                     cfg->local_cidr_count);
    log_config_cidrs("allow_networks", cfg->allow_cidr,
                     cfg->allow_cidr_count);
    log_config_ports(cfg);
    fprintf(stderr, "  ├─ remote_map_size = %u\n",
            cfg->remote_map_size);
    fprintf(stderr, "  ├─ drop_map_size = %u\n", cfg->drop_map_size);
    fprintf(stderr, "  ├─ reply_idle_seconds = %d\n",
            cfg->reply_idle_seconds);
    fprintf(stderr, "  └─ metrics_port = %d\n", cfg->metrics_port);
}
