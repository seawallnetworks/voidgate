#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# The entries for a kernel before 5.12, voidgate_xdp_pl and voidgate_tc_pl,
# have no atomic OR, nor call a function that has one: that kernel's
# verifier refuses a program with one anywhere (Seawall proposal 0023 §2).
# No 5.10 kernel runs the tests, so the object is read instead.
set -euo pipefail

obj=${1:-src/bpf/voidgate.bpf.o}
dis=$(llvm-objdump -dr --no-show-raw-insn "$obj")

# function: its atomic instructions, and the functions it calls
report=$(awk '
    /^[0-9a-f]+ <[A-Za-z_0-9]+>:$/ && !/<LBB/ {
        f = substr($2, 2, length($2) - 3)
    }
    /[[:space:]]lock[[:space:]]/ { print f, "atomic" }
    /R_BPF_64_32/ { print f, "calls", $NF }
' <<< "$dis" | sort -u)

atomic() {
    grep -qx "$1 atomic" <<< "$report"
}

fail=0
for entry in voidgate_xdp_pl voidgate_tc_pl; do
    if ! grep -q "<$entry>:" <<< "$dis"; then
        echo "syn-plain: no $entry in $obj" >&2
        fail=1
        continue
    fi
    calls=$(awk -v e="$entry" '$1 == e && $2 == "calls" { print $3 }' \
            <<< "$report")
    for f in "$entry" $calls; do
        if atomic "$f"; then
            echo "syn-plain: $entry: $f has an atomic instruction" >&2
            fail=1
        fi
    done
done

# and the check sees one where there is one
if ! atomic vg_syn_filter; then
    echo "syn-plain: no atomic OR in vg_syn_filter: the check is blind" >&2
    fail=1
fi

(( fail == 0 )) && echo "syn-plain: ok"
exit "$fail"
