
/* SPDX-License-Identifier: Apache-2.0 */

#include "config.h"
#include "ipaddr.h"
#include "log.h"

#include <stdio.h>


/* a list line stays under SW_LOG_LINE_MAX: a long one goes on in another */
#define VG_LOG_LIST_MAX  1024


int vg_verbose;


static void log_config_cidrs(const char *key, const struct vg_cidr *cidrs,
    int count);
static void log_config_ports(const struct vg_config *cfg);


static void
log_config_cidrs(const char *key, const struct vg_cidr *cidrs, int count)
{
    int     i;
    size_t  used;
    char    buf[80], list[VG_LOG_LIST_MAX];

    used = 0;
    list[0] = '\0';

    for (i = 0; i < count; i++) {
        vg_cidr_to_str(&cidrs[i], buf, sizeof(buf));

        if (used + sizeof(buf) + 2 > sizeof(list)) {
            sw_log_debug("  ├─ %s = %s,", key, list);
            used = 0;
            list[0] = '\0';
        }

        used += (size_t) snprintf(list + used, sizeof(list) - used, "%s%s",
                                  used == 0 ? "" : ", ", buf);
    }

    sw_log_debug("  ├─ %s = %s", key, list);
}


static void
log_config_ports(const struct vg_config *cfg)
{
    int     i;
    size_t  used;
    char    list[VG_MAX_ALLOW_PORTS * 7 + 1];

    used = 0;
    list[0] = '\0';

    for (i = 0; i < cfg->allow_port_count; i++) {
        used += (size_t) snprintf(list + used, sizeof(list) - used, "%s%u",
                                  i == 0 ? "" : ", ", cfg->allow_ports[i]);
    }

    sw_log_debug("  ├─ allow_ports = %s", list);
}


void
vg_log_config(const struct vg_config *cfg, const char *hook)
{
    if (!sw_log_enabled(SW_LOG_DEBUG)) {
        return;
    }

    sw_log_debug("attached at %s", hook);
    sw_log_debug("active configuration");
    sw_log_debug("  ├─ interface = %s", cfg->interface);
    sw_log_debug("  ├─ xdp_mode = %s", cfg->xdp_mode);
    sw_log_debug("  ├─ hook = %s", cfg->hook);
    sw_log_debug("  ├─ wake_pps = %llu",
                 (unsigned long long) cfg->wake_pps);
    sw_log_debug("  ├─ wake_mbps = %llu",
                 (unsigned long long) cfg->wake_mbps);
    sw_log_debug("  ├─ idle_poll_ms = %d", cfg->idle_poll_ms);
    sw_log_debug("  ├─ clear_seconds = %d", cfg->clear_seconds);
    sw_log_debug("  ├─ threshold_pps = %llu",
                 (unsigned long long) cfg->threshold_pps);
    sw_log_debug("  ├─ threshold_mbps = %llu",
                 (unsigned long long) cfg->threshold_mbps);
    sw_log_debug("  ├─ ban_time = %d", cfg->ban_time);
    sw_log_debug("  ├─ aggregate_k = %d", cfg->aggregate_k);
    log_config_cidrs("local_networks", cfg->local_cidr,
                     cfg->local_cidr_count);
    log_config_cidrs("allow_networks", cfg->allow_cidr,
                     cfg->allow_cidr_count);
    log_config_ports(cfg);
    sw_log_debug("  ├─ remote_map_size = %u", cfg->remote_map_size);
    sw_log_debug("  ├─ drop_map_size = %u", cfg->drop_map_size);
    sw_log_debug("  ├─ reply_idle_seconds = %d", cfg->reply_idle_seconds);
    sw_log_debug("  └─ metrics_port = %d", cfg->metrics_port);
}
