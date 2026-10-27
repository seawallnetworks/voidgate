# SPDX-License-Identifier: Apache-2.0
# ARMED IPv6: NDP / SSH / DHCPv6 whitelist before the drop LPM.
# Fixture (t/conf/xdp.conf): local 2001:db8::10, allow_ports 22.

use VG::Test;

run_xdp_blocks();

__DATA__

=== TEST 1: IPv6 NDP always PASS
--- packets: ipv6 icmpv6 fe80::1 > ff02::1 type=135 hop=255
--- verdict: XDP_PASS



=== TEST 2: global-address NDP with hop limit 255 passes from dropped src
--- setup: drop 2001:db8::bad/128
--- packets
ipv6 icmpv6 2001:db8::bad > 2001:db8::10 type=133 hop=255
ipv6 icmpv6 2001:db8::bad > 2001:db8::10 type=134 hop=255
ipv6 icmpv6 2001:db8::bad > 2001:db8::10 type=135 hop=255
ipv6 icmpv6 2001:db8::bad > 2001:db8::10 type=136 hop=255
ipv6 icmpv6 2001:db8::bad > 2001:db8::10 type=137 hop=255
--- verdict
XDP_PASS
XDP_PASS
XDP_PASS
XDP_PASS
XDP_PASS



=== TEST 3: NDP with hop limit below 255 is not a whitelist
--- setup: drop 2001:db8::bad/128
--- packets
ipv6 icmpv6 2001:db8::bad > 2001:db8::10 type=133 hop=64
ipv6 icmpv6 2001:db8::bad > 2001:db8::10 type=134 hop=64
ipv6 icmpv6 2001:db8::bad > 2001:db8::10 type=135 hop=64
ipv6 icmpv6 2001:db8::bad > 2001:db8::10 type=136 hop=254
ipv6 icmpv6 2001:db8::bad > 2001:db8::10 type=137 hop=1
--- verdict
XDP_DROP
XDP_DROP
XDP_DROP
XDP_DROP
XDP_DROP



=== TEST 4: non-NDP ICMPv6 with hop limit 255 from dropped src is XDP_DROP
--- setup: drop 2001:db8::bad/128
--- packets
ipv6 icmpv6 2001:db8::bad > 2001:db8::10 type=128 hop=255
ipv6 icmpv6 2001:db8::bad > 2001:db8::10 type=138 hop=255
--- verdict
XDP_DROP
XDP_DROP



=== TEST 5: armed + dropped IPv6 src is XDP_DROP
--- setup: drop 2001:db8::bad/128
--- packets: ipv6 udp [2001:db8::bad]:12345 > [2001:db8::10]:80
--- verdict: XDP_DROP



=== TEST 6: IPv6 SSH dport 22 passes from dropped src
--- setup: drop 2001:db8::bad/128
--- packets: ipv6 tcp [2001:db8::bad]:40000 > [2001:db8::10]:22
--- verdict: XDP_PASS



=== TEST 7: IPv6 TCP sport 22 from dropped src is not a whitelist
--- setup: drop 2001:db8::bad/128
--- packets: ipv6 tcp [2001:db8::bad]:22 > [2001:db8::10]:80
--- verdict: XDP_DROP



=== TEST 8: DHCPv6 server reply 547->546 to local passes from dropped src
--- setup: drop 2001:db8::bad/128
--- packets: ipv6 udp [2001:db8::bad]:547 > [2001:db8::10]:546
--- verdict: XDP_PASS



=== TEST 9: UDP sport 547 from dropped IPv6 src is not a whitelist
--- setup: drop 2001:db8::bad/128
--- packets: ipv6 udp [2001:db8::bad]:547 > [2001:db8::10]:80
--- verdict: XDP_DROP



=== TEST 10: UDP sport 546 from dropped IPv6 src is not a whitelist
--- setup: drop 2001:db8::bad/128
--- packets: ipv6 udp [2001:db8::bad]:546 > [2001:db8::10]:80
--- verdict: XDP_DROP



=== TEST 11: non-dropped IPv6 is XDP_PASS
--- setup: drop 2001:db8::bad/128
--- packets: ipv6 udp [2001:db8::1]:12345 > [2001:db8::10]:80
--- verdict: XDP_PASS



=== TEST 12: IPv6 header of another version has no addresses: passed
--- setup: drop 2001:db8::bad/128
--- packets: ipv6 udp [2001:db8::bad]:12345 > [2001:db8::10]:80 set@14=80
--- verdict: XDP_PASS
--- counters: rx_pkts=1 passed=0 dropped=0 parse_err=1
