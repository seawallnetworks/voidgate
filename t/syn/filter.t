# First-SYN drop (Seawall proposal 0023): the generational Bloom filter's
# verdicts, the drop LPM ahead of it for ports not in allow_ports, and
# pure SYNs never counted against their source. Runs with t/conf/syn.conf:
# sudo VG_FIXTURE=syn t/bin/run.
#
# A packets line's sleep is the gap wanted less about 30 ms: the harness
# waits at least 20 ms after each frame for the counters to land. Each
# block has its own addresses and sequence numbers: the filter remembers
# across a disarm and an arm 4.5 s long.
use VG::Test;

run_xdp_blocks();

__DATA__

=== TEST 1: a first SYN is dropped
--- engage
--- packets: ipv4 tcp 203.0.113.100:40000 > 198.51.100.10:80 seq=1001
--- verdict: XDP_DROP
--- counters: syn_unproven=1 syn_guard_dropped=1 dropped=1



=== TEST 2: IPv6: a first SYN is dropped
--- engage
--- packets: ipv6 tcp [2001:db8::100]:40000 > [2001:db8::10]:80 seq=1002
--- verdict: XDP_DROP
--- counters: syn_unproven=1 syn_guard_dropped=1 dropped=1



=== TEST 3: a retransmission 0.95 s later passes
--- engage
--- packets
ipv4 tcp 203.0.113.101:40000 > 198.51.100.10:80 seq=1003
sleep 0.92
ipv4 tcp 203.0.113.101:40000 > 198.51.100.10:80 seq=1003
--- verdict
XDP_DROP
XDP_PASS
--- counters: syn_unproven=2 syn_guard_dropped=1 syn_guard_retrans=1



=== TEST 4: IPv6: a retransmission 1 s later passes
--- engage
--- packets
ipv6 tcp [2001:db8::101]:40000 > [2001:db8::10]:80 seq=1004
sleep 0.97
ipv6 tcp [2001:db8::101]:40000 > [2001:db8::10]:80 seq=1004
--- verdict
XDP_DROP
XDP_PASS
--- counters: syn_unproven=2 syn_guard_dropped=1 syn_guard_retrans=1



=== TEST 5: a duplicate within 10 ms is dropped too
--- engage
--- packets: 2x ipv4 tcp 203.0.113.102:40000 > 198.51.100.10:80 seq=1005
--- verdict: XDP_DROP
--- counters: syn_unproven=2 syn_guard_dropped=2 syn_guard_retrans=0 dropped=2



=== TEST 6: Windows' retransmission 3.3 s later passes
--- engage
--- packets
ipv4 tcp 203.0.113.103:40000 > 198.51.100.10:80 seq=1006
sleep 3.27
ipv4 tcp 203.0.113.103:40000 > 198.51.100.10:80 seq=1006
--- verdict
XDP_DROP
XDP_PASS



=== TEST 7: past the window, the next retransmission passes
--- engage
--- packets
ipv4 tcp 203.0.113.104:40000 > 198.51.100.10:80 seq=1007
sleep 4.6
ipv4 tcp 203.0.113.104:40000 > 198.51.100.10:80 seq=1007
sleep 0.97
ipv4 tcp 203.0.113.104:40000 > 198.51.100.10:80 seq=1007
--- verdict
XDP_DROP
XDP_DROP
XDP_PASS
--- counters: syn_guard_dropped=2 syn_guard_retrans=1



=== TEST 8: a new sequence number is a new first SYN
--- engage
--- packets
ipv4 tcp 203.0.113.105:40000 > 198.51.100.10:80 seq=1008
sleep 0.97
ipv4 tcp 203.0.113.105:40000 > 198.51.100.10:80 seq=2008
--- verdict
XDP_DROP
XDP_DROP



=== TEST 9: SYN-ACK, ACK and RST aren't SYNs
--- engage
--- packets
ipv4 tcp 203.0.113.106:40000 > 198.51.100.10:80 seq=1009 flags=SA
ipv4 tcp 203.0.113.106:40000 > 198.51.100.10:80 seq=1009 flags=A
ipv4 tcp 203.0.113.106:40000 > 198.51.100.10:80 seq=1009 flags=R
--- verdict
XDP_PASS
XDP_PASS
XDP_PASS
--- counters: syn_unproven=0 syn_guard_dropped=0



=== TEST 10: in standby, a SYN is counted and passed
--- packets: ipv4 tcp 203.0.113.107:40000 > 198.51.100.10:80 seq=1010
--- verdict: XDP_PASS
--- counters: syn_unproven=1 syn_guard_dropped=0



=== TEST 11: allow_networks is exempt
--- engage
--- packets: ipv4 tcp 192.0.2.99:40000 > 198.51.100.10:80 seq=1011
--- verdict: XDP_PASS
--- counters: syn_unproven=0 syn_guard_dropped=0



=== TEST 12: allow_ports isn't: SSH waits once, then connects
--- engage
--- packets
ipv4 tcp 203.0.113.108:40000 > 198.51.100.10:22 seq=1012
sleep 0.97
ipv4 tcp 203.0.113.108:40000 > 198.51.100.10:22 seq=1012
ipv4 tcp 203.0.113.108:40000 > 198.51.100.10:22 seq=1013 flags=A
--- verdict
XDP_DROP
XDP_PASS
XDP_PASS
--- counters: syn_guard_dropped=1 syn_guard_retrans=1



=== TEST 13: a blocked address' retransmitted SYN is still dropped
--- engage
--- setup: block 203.0.113.110/32
--- packets
ipv4 tcp 203.0.113.110:40000 > 198.51.100.10:80 seq=1014
sleep 0.97
ipv4 tcp 203.0.113.110:40000 > 198.51.100.10:80 seq=1014
--- verdict
XDP_DROP
XDP_DROP
--- counters: dropped=2 syn_unproven=0 syn_guard_dropped=0



=== TEST 14: a blocked address' SYN to a port not in allow_ports isn't written
The LPM drops it first: unblocked, its retransmission is a first SYN.
--- engage
--- setup: block 203.0.113.111/32
--- packets
ipv4 tcp 203.0.113.111:40000 > 198.51.100.10:80 seq=1015
ctl unblock 203.0.113.111/32
sleep 0.97
ipv4 tcp 203.0.113.111:40000 > 198.51.100.10:80 seq=1015
--- verdict
XDP_DROP
XDP_DROP
--- counters: dropped=2 syn_unproven=1 syn_guard_dropped=1 syn_guard_retrans=0



=== TEST 15: IPv6: a blocked address' SYN to a port not in allow_ports
--- engage
--- setup: block 2001:db8::111/128
--- packets
ipv6 tcp [2001:db8::111]:40000 > [2001:db8::10]:80 seq=1016
ctl unblock 2001:db8::111/128
sleep 0.97
ipv6 tcp [2001:db8::111]:40000 > [2001:db8::10]:80 seq=1016
--- verdict
XDP_DROP
XDP_DROP
--- counters: dropped=2 syn_unproven=1 syn_guard_dropped=1 syn_guard_retrans=0



=== TEST 16: a blocked address' SYN to SSH waits once, then connects
--- engage
--- setup: block 203.0.113.112/32
--- packets
ipv4 tcp 203.0.113.112:40000 > 198.51.100.10:22 seq=1017
sleep 0.97
ipv4 tcp 203.0.113.112:40000 > 198.51.100.10:22 seq=1017
ipv4 tcp 203.0.113.112:40000 > 198.51.100.10:22 seq=1018 flags=A
--- verdict
XDP_DROP
XDP_PASS
XDP_PASS
--- counters: dropped=1 syn_unproven=2 syn_guard_dropped=1 syn_guard_retrans=1



=== TEST 17: passing the filter isn't a pass: blocked meanwhile, dropped
--- engage
--- packets
ipv4 tcp 203.0.113.113:40000 > 198.51.100.10:80 seq=1019
ctl block 203.0.113.113/32
sleep 0.97
ipv4 tcp 203.0.113.113:40000 > 198.51.100.10:80 seq=1019
--- verdict
XDP_DROP
XDP_DROP
--- counters: dropped=2 syn_guard_dropped=1



=== TEST 18: pure SYNs aren't counted against their source; UDP is
At 40 a second each, over threshold_pps, under wake_pps.
--- packets
4x ipv4 tcp 203.0.113.114:40000 > 198.51.100.10:80 seq=1020
sleep 0.3
4x ipv4 tcp 203.0.113.114:40000 > 198.51.100.10:80 seq=1020
sleep 0.3
4x ipv4 tcp 203.0.113.114:40000 > 198.51.100.10:80 seq=1020
4x ipv4 udp 203.0.113.115:40000 > 198.51.100.10:80
sleep 0.3
4x ipv4 udp 203.0.113.115:40000 > 198.51.100.10:80
sleep 0.3
4x ipv4 udp 203.0.113.115:40000 > 198.51.100.10:80
--- verdict
XDP_PASS
XDP_PASS
XDP_PASS
XDP_PASS
XDP_PASS
XDP_DROP
--- counters: syn_unproven=12 syn_guard_dropped=0
--- blocks: 203.0.113.115/32



=== TEST 19: IPv6: pure SYNs aren't counted against their source
--- packets
4x ipv6 tcp [2001:db8::114]:40000 > [2001:db8::10]:80 seq=1021
sleep 0.3
4x ipv6 tcp [2001:db8::114]:40000 > [2001:db8::10]:80 seq=1021
sleep 0.3
4x ipv6 tcp [2001:db8::114]:40000 > [2001:db8::10]:80 seq=1021
--- verdict
XDP_PASS
XDP_PASS
XDP_PASS
--- counters: syn_unproven=12
--- blocks
