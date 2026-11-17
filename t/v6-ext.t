# SPDX-License-Identifier: Apache-2.0
# IPv6 extension headers: the walk finds L4 ports for the whitelist, but a
# chain cannot be used to smuggle exempt ports past the drop LPM.
# ext= lists headers in wire order (first one follows the IPv6 header).

use VG::Test;

run_xdp_blocks();

__DATA__

=== TEST 1: IPv6 extension preserves SSH exemption (hopopts)
--- setup: block 2001:db8::bad/128
--- packets: ipv6 tcp [2001:db8::bad]:40000 > [2001:db8::10]:22 ext=hopopts
--- verdict: XDP_PASS



=== TEST 2: IPv6 extension does not exempt remote source port 22 (hopopts)
--- setup: block 2001:db8::bad/128
--- packets: ipv6 tcp [2001:db8::bad]:22 > [2001:db8::10]:80 ext=hopopts
--- verdict: XDP_DROP



=== TEST 3: IPv6 extension preserves SSH exemption (dstopts)
--- setup: block 2001:db8::bad/128
--- packets: ipv6 tcp [2001:db8::bad]:40000 > [2001:db8::10]:22 ext=dstopts
--- verdict: XDP_PASS



=== TEST 4: IPv6 extension does not exempt remote source port 22 (dstopts)
--- setup: block 2001:db8::bad/128
--- packets: ipv6 tcp [2001:db8::bad]:22 > [2001:db8::10]:80 ext=dstopts
--- verdict: XDP_DROP



=== TEST 5: IPv6 extension preserves SSH exemption (routing)
--- setup: block 2001:db8::bad/128
--- packets: ipv6 tcp [2001:db8::bad]:40000 > [2001:db8::10]:22 ext=routing
--- verdict: XDP_PASS



=== TEST 6: IPv6 extension does not exempt remote source port 22 (routing)
--- setup: block 2001:db8::bad/128
--- packets: ipv6 tcp [2001:db8::bad]:22 > [2001:db8::10]:80 ext=routing
--- verdict: XDP_DROP



=== TEST 7: IPv6 extension preserves SSH exemption (ah)
--- setup: block 2001:db8::bad/128
--- packets: ipv6 tcp [2001:db8::bad]:40000 > [2001:db8::10]:22 ext=ah
--- verdict: XDP_PASS



=== TEST 8: IPv6 extension does not exempt remote source port 22 (ah)
--- setup: block 2001:db8::bad/128
--- packets: ipv6 tcp [2001:db8::bad]:22 > [2001:db8::10]:80 ext=ah
--- verdict: XDP_DROP



=== TEST 9: IPv6 extension preserves SSH exemption (first fragment)
--- setup: block 2001:db8::bad/128
--- packets: ipv6 tcp [2001:db8::bad]:40000 > [2001:db8::10]:22 ext=frag
--- verdict: XDP_PASS



=== TEST 10: IPv6 extension does not exempt remote source port 22 (first fragment)
--- setup: block 2001:db8::bad/128
--- packets: ipv6 tcp [2001:db8::bad]:22 > [2001:db8::10]:80 ext=frag
--- verdict: XDP_DROP



=== TEST 11: IPv6 bounded extension chain reaches SSH
--- setup: block 2001:db8::bad/128
--- packets: ipv6 tcp [2001:db8::bad]:40000 > [2001:db8::10]:22 ext=dstopts*8
--- verdict: XDP_PASS



=== TEST 12: overlong extension chain cannot supply exempt ports
--- setup: block 2001:db8::bad/128
--- packets
ipv6 tcp [2001:db8::bad]:40000 > [2001:db8::10]:22 ext=hopopts,dstopts*8
--- verdict: XDP_DROP



=== TEST 13: extension before non-first fragment does not expose ports
--- setup: block 2001:db8::bad/128
--- packets
ipv6 tcp [2001:db8::bad]:40000 > [2001:db8::10]:22 ext=hopopts,frag:8
--- verdict: XDP_DROP



=== TEST 14: IPv6 chained extensions preserve DHCPv6 exemption
--- setup: block 2001:db8::bad/128
--- packets
ipv6 udp [2001:db8::bad]:546 > [2001:db8::10]:547 ext=hopopts,dstopts
--- verdict: XDP_PASS



=== TEST 15: IPv6 extension preserves global-address NDP exemption
--- setup: block 2001:db8::bad/128
--- packets
ipv6 icmpv6 2001:db8::bad > 2001:db8::10 type=135 hop=255 ext=dstopts
--- verdict: XDP_PASS



=== TEST 16: extension does not exempt NDP with hop limit below 255
--- setup: block 2001:db8::bad/128
--- packets
ipv6 icmpv6 2001:db8::bad > 2001:db8::10 type=135 hop=64 ext=dstopts
--- verdict: XDP_DROP



=== TEST 17: truncated IPv6 extension from blocked src is XDP_DROP
--- setup: block 2001:db8::bad/128
--- packets
ipv6 icmpv6 2001:db8::bad > 2001:db8::10 type=135 hop=255 ext=dstopts set@55=255
--- verdict: XDP_DROP
--- counters: dropped=1 parse_err=1
