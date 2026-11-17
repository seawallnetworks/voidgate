# SPDX-License-Identifier: Apache-2.0
# Test::Base glue for the real voidgate daemon started by t/bin/run.
#
# XDP blocks:
#   === name
#   --- idle                  (optional: leave the gate disarmed)
#   --- setup                 (optional: ctl commands, each must reply ok)
#   block 203.0.113.1/32
#   --- packets               (one VG::Packet spec per line)
#   ipv4 udp 203.0.113.1:68 > 198.51.100.10:80
#   --- verdict               (one XDP_PASS / XDP_DROP per packet line)
#   XDP_DROP
#   --- counters: rx_pkts=1 dropped=0     (optional: summed stats deltas)
#
# ctl blocks:
#   --- input: block 10.1.2.3/24
#   --- expected: ok
#   --- blocks: 10.1.2.0/24   (optional: the listed blocks' cidrs)

package VG::Test;

use Test::Base -Base;

use Time::HiRes qw(sleep);
use VG::Ctl qw(ctl stats);
use VG::Packet qw(build send_frame);

our @EXPORT = qw(run_xdp_blocks run_ctl_blocks);

my @COUNTERS = qw(rx_pkts rx_bytes passed dropped non_ip map_full parse_err);

my $lines = sub {
    my ($text) = @_;

    return grep { /\S/ } map { s/^\s+|\s+$//gr } split /\n/, $text // '';
};

my $guard = sub {
    unless ($ENV{VG_PEER} && -S $VG::Ctl::PATH) {
        plan skip_all => 'needs the daemon: sudo t/bin/run';
    }
};

# Fresh gate for every block: disarm flushes drop_v4/v6 and clears armed.
my $reset = sub {
    my ($block) = @_;
    my $name = $block->name;

    for my $cmd ('disarm', exists $block->{idle} ? () : 'arm',
                 $lines->($block->setup))
    {
        my $r = ctl($cmd);

        die "block '$name': '$cmd' replied '$r'" unless $r eq "ok\n";
    }
};

# Send one frame and read the verdict from the daemon's XDP counters.
my $send = sub {
    my ($spec, $sum) = @_;
    my $frame = build($spec);
    my $before = stats();
    my $after;

    send_frame($ENV{VG_PEER}, $frame);

    for (1 .. 100) {
        $after = stats();
        last if $after->{rx_pkts} > $before->{rx_pkts};
        sleep 0.01;
    }

    # rx_pkts is bumped first; let the rest of the XDP run land.
    sleep 0.02;
    $after = stats();

    my %d = map { $_ => $after->{$_} - $before->{$_} } @COUNTERS;

    $sum->{$_} += $d{$_} for @COUNTERS;

    return "no frame reached XDP" if $d{rx_pkts} == 0;
    return "$d{rx_pkts} frames reached XDP (noise?)" if $d{rx_pkts} > 1;
    return $d{dropped} ? 'XDP_DROP' : 'XDP_PASS';
};


sub run_xdp_blocks() {
    $guard->();

    my @blocks = blocks;
    my $tests = 0;

    $tests += defined $_->counters ? 2 : 1 for @blocks;
    plan tests => $tests;

    for my $block (@blocks) {
        my %sum;
        my @specs = $lines->($block->packets);
        my @got;

        $reset->($block);
        push @got, $send->($_, \%sum) for @specs;
        is(join("\n", @got), join("\n", $lines->($block->verdict)),
           $block->name);

        if (defined $block->counters) {
            my %want = $block->counters =~ /(\w+)=(\d+)/g;
            my %got = map { $_ => $sum{$_} } keys %want;

            is_deeply(\%got, \%want, $block->name . ': counters');
        }
    }
}


sub run_ctl_blocks() {
    $guard->();

    my @blocks = blocks;
    my $tests = 0;

    $tests += defined $_->blocks ? 2 : 1 for @blocks;
    plan tests => $tests;

    for my $block (@blocks) {
        ctl('disarm');
        is(ctl($block->input), $block->expected . "\n", $block->name);

        if (defined $block->blocks) {
            my @got = ctl('blocks') =~ /^id=\d+ cidr=(\S+) /mg;

            is_deeply(\@got, [$lines->($block->blocks)],
                      $block->name . ': blocks');
        }
    }
}
