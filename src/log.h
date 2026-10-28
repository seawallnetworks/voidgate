
/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Logging is libsw's sw_log (Seawall proposal 0011): -v shows its debug
 * lines; -vv adds the per-remote and idle-tick ones, which flood.
 */

#ifndef _VG_LOG_H_INCLUDED_
#define _VG_LOG_H_INCLUDED_


#include <sw/log.h>


#define vg_vvlog(...)                                                     \
    do {                                                                  \
        if (vg_verbose >= 2) {                                            \
            sw_log_debug(__VA_ARGS__);                                    \
        }                                                                 \
    } while (0)


struct vg_config;


extern int vg_verbose;


/* The running config, a debug line a key. */
void vg_log_config(const struct vg_config *cfg, const char *hook);


#endif /* _VG_LOG_H_INCLUDED_ */
