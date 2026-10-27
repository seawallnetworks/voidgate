# SPDX-License-Identifier: Apache-2.0
# ARMED IPv4: allow / SSH / DHCP whitelist before the drop LPM.
# Fixture (t/conf/xdp.conf): local 198.51.100.10, allow 192.0.2.99, port 22.

use VG::Test;

run_xdp_blocks();

__DATA__

=== TEST 1: armed + dropped src is XDP_DROP
--- setup: drop 203.0.113.1/32
--- packets: ipv4 udp 203.0.113.1:12345 > 198.51.100.10:80
--- verdict: XDP_DROP
--- counters: rx_pkts=1 dropped=1



=== TEST 2: SSH dport 22 passes even from dropped src
--- setup: drop 203.0.113.1/32
--- packets: ipv4 tcp 203.0.113.1:40000 > 198.51.100.10:22
--- verdict: XDP_PASS



=== TEST 3: TCP sport 22 from dropped src is not a whitelist
--- setup: drop 203.0.113.1/32
--- packets: ipv4 tcp 203.0.113.1:22 > 198.51.100.10:80
--- verdict: XDP_DROP



=== TEST 4: DHCP server reply 67->68 to local passes from dropped src
--- setup: drop 203.0.113.1/32
--- packets: ipv4 udp 203.0.113.1:67 > 198.51.100.10:68
--- verdict: XDP_PASS



=== TEST 5: DHCP server reply 67->68 to broadcast passes
--- setup: drop 203.0.113.1/32
--- packets: ipv4 udp 203.0.113.1:67 > 255.255.255.255:68
--- verdict: XDP_PASS



=== TEST 6: DHCP client request 68->67 to local passes
--- setup: drop 203.0.113.1/32
--- packets: ipv4 udp 203.0.113.1:68 > 198.51.100.10:67
--- verdict: XDP_PASS



=== TEST 7: UDP sport 68 from dropped src is not a whitelist
--- setup: drop 203.0.113.1/32
--- packets: ipv4 udp 203.0.113.1:68 > 198.51.100.10:80
--- verdict: XDP_DROP



=== TEST 8: UDP sport 67 from dropped src is not a whitelist
--- setup: drop 203.0.113.1/32
--- packets: ipv4 udp 203.0.113.1:67 > 198.51.100.10:80
--- verdict: XDP_DROP



=== TEST 9: UDP dport 67 from a non-DHCP port is not a whitelist
--- setup: drop 203.0.113.1/32
--- packets: ipv4 udp 203.0.113.1:12345 > 198.51.100.10:67
--- verdict: XDP_DROP



=== TEST 10: DHCP ports to a non-local unicast dest are not a whitelist
--- setup: drop 203.0.113.1/32
--- packets: ipv4 udp 203.0.113.1:67 > 198.51.100.77:68
--- verdict: XDP_DROP



=== TEST 11: VLAN-tagged dropped src is XDP_DROP
--- setup: drop 203.0.113.1/32
--- packets: ipv4 udp 203.0.113.1:12345 > 198.51.100.10:80 vlan=1
--- verdict: XDP_DROP



=== TEST 12: non-first fragment from dropped src is XDP_DROP
--- setup: drop 203.0.113.1/32
--- packets: ipv4 frag 203.0.113.1 > 198.51.100.10 off=8
--- verdict: XDP_DROP



=== TEST 13: allow_v4 prefix passes
--- setup: drop 203.0.113.1/32
--- packets: ipv4 udp 192.0.2.99:12345 > 198.51.100.10:80
--- verdict: XDP_PASS



=== TEST 14: non-dropped src is XDP_PASS when armed
--- setup: drop 203.0.113.1/32
--- packets: ipv4 udp 198.51.100.8:12345 > 198.51.100.10:80
--- verdict: XDP_PASS
--- counters: rx_pkts=1 passed=1 dropped=0



=== TEST 15: IHL below 5 from dropped src is XDP_DROP
--- setup: drop 203.0.113.1/32
--- packets: ipv4 udp 203.0.113.1:12345 > 198.51.100.10:80 set@14=68
--- verdict: XDP_DROP
--- counters: rx_pkts=1 dropped=1 parse_err=1



=== TEST 16: IHL past the frame end from dropped src is XDP_DROP
--- setup: drop 203.0.113.1/32
--- packets: ipv4 udp 203.0.113.1:12345 > 198.51.100.10:80 set@14=79
--- verdict: XDP_DROP
--- counters: rx_pkts=1 dropped=1 parse_err=1



=== TEST 17: bad IHL cannot expose the SSH exemption
--- setup: drop 203.0.113.1/32
--- packets: ipv4 tcp 203.0.113.1:40000 > 198.51.100.10:22 set@14=79
--- verdict: XDP_DROP



=== TEST 18: bad IHL from a non-dropped src still passes
--- setup: drop 203.0.113.1/32
--- packets: ipv4 udp 198.51.100.8:12345 > 198.51.100.10:80 set@14=68
--- verdict: XDP_PASS
--- counters: rx_pkts=1 dropped=0 parse_err=1



=== TEST 19: IPv4 header of another version is judged without ports
--- setup: drop 203.0.113.1/32
--- packets: ipv4 tcp 203.0.113.1:40000 > 198.51.100.10:22 set@14=85
--- verdict: XDP_DROP
--- counters: rx_pkts=1 dropped=1 parse_err=1
