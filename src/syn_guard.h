/* SPDX-License-Identifier: Apache-2.0 */

#ifndef _VG_SYN_GUARD_H_INCLUDED_
#define _VG_SYN_GUARD_H_INCLUDED_

#include "bpf/voidgate.h"

#include <stdint.h>


struct vg_syn;

int vg_syn_atomic_probe(void);
struct vg_syn *vg_syn_start(struct vg_syn_block *bloom, uint32_t blocks_log2,
    struct vg_syn_marks *marks);
void vg_syn_armed(struct vg_syn *s, int armed);
void vg_syn_stop(struct vg_syn *s);
uint64_t vg_syn_gen_now(void);

#endif /* _VG_SYN_GUARD_H_INCLUDED_ */
