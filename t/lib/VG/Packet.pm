# SPDX-License-Identifier: Apache-2.0
# Build Ethernet frames from a one-line spec and send them on a raw socket.
#
#   ipv4 udp 203.0.113.1:68 > 198.51.100.10:80
#   ipv4 udp 203.0.113.1:12345 > 198.51.100.10:80 vlan=1
#   ipv4 frag 203.0.113.1 > 198.51.100.10 off=8
#   ipv6 tcp [2001:db8::bad]:40000 > [2001:db8::10]:22 ext=hopopts,dstopts*8
#   ipv6 icmpv6 fe80::1 > ff02::1 type=135 hop=255
#   ipv4 tcp 203.0.113.1:40000 > 198.51.100.10:80 seq=7 flags=SA
#   ... set@55=255
#
# TCP is a SYN with sequence number 0 unless seq= and flags= (letters of
# FSRPAU) say otherwise.
# ext= lists IPv6 extension headers in wire order; frag:N sets the raw
# frag_off field. set@I=V patches frame byte I after the frame is built.

package VG::Packet;

use strict;
use warnings;

use Carp qw(croak);
use Socket qw(AF_INET AF_INET6 SOCK_RAW inet_pton);

our @EXPORT_OK = qw(build send_frame);
use Exporter 'import';

use constant {
    ETH_P_IP     => 0x0800,
    ETH_P_IPV6   => 0x86dd,
    ETH_P_8021Q  => 0x8100,
    PF_PACKET    => 17,
    SIOCGIFINDEX => 0x8933,
    PROTO_TCP    => 6,
    PROTO_UDP    => 17,
    PROTO_ICMPV6 => 58,
};

my %TCP_FLAG = (F => 0x01, S => 0x02, R => 0x04, P => 0x08, A => 0x10,
                U => 0x20);

my %EXT = (
    hopopts => 0,
    routing => 43,
    frag    => 44,
    ah      => 51,
    dstopts => 60,
);


sub _eth {
    my ($proto) = @_;

    return pack('C6 C6 n', 2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, $proto);
}


sub _cksum {
    my ($data) = @_;
    my $s = 0;

    $data .= "\0" if length($data) % 2;
    $s += $_ for unpack('n*', $data);
    $s = ($s & 0xffff) + ($s >> 16) while $s >> 16;
    return ~$s & 0xffff;
}


sub _addr {
    my ($family, $text) = @_;
    my $a = inet_pton($family, $text);

    croak "bad address '$text'" unless defined $a;
    return $a;
}


# "a.b.c.d:port", "[v6]:port" or a bare address.
sub _endpoint {
    my ($fam, $tok) = @_;

    if ($tok =~ /^\[(.+)\]:(\d+)$/) {
        return ($1, $2);
    }

    if ($fam eq 'ipv4' && $tok =~ /^([\d.]+):(\d+)$/) {
        return ($1, $2);
    }

    return ($tok, 0);
}


sub _l4 {
    my ($proto, $sport, $dport, $opt) = @_;

    if ($proto eq 'tcp') {
        my $flags = 0;

        for (split //, $opt->{flags} // 'S') {
            croak "unknown TCP flag '$_'" unless exists $TCP_FLAG{$_};
            $flags |= $TCP_FLAG{$_};
        }

        return (PROTO_TCP,
                pack('n n N N C C n n n', $sport, $dport, $opt->{seq} // 0, 0,
                     5 << 4, $flags, 0, 0, 0));
    }

    if ($proto eq 'udp') {
        return (PROTO_UDP, pack('n n n n', $sport, $dport, 8, 0));
    }

    if ($proto eq 'icmpv6') {
        return (PROTO_ICMPV6,
                pack('C C n N', $opt->{type} // 0, 0, 0, 0));
    }

    croak "unknown protocol '$proto'";
}


sub _v6_exts {
    my ($list, $next) = @_;
    my @names;
    my $out = '';

    for my $item (split /,/, $list) {
        my ($name, $count) = $item =~ /^([\w:]+)(?:\*(\d+))?$/
            or croak "bad ext '$item'";
        push @names, ($name) x ($count // 1);
    }

    # Build from the innermost header outwards so each knows its next.
    for my $name (reverse @names) {
        my ($type, $arg) = split /:/, $name, 2;
        my $code = $EXT{$type};

        croak "unknown ext '$type'" unless defined $code;

        if ($type eq 'frag') {
            $out = pack('C C n N', $next, 0, $arg // 0, 0) . $out;

        } elsif ($type eq 'ah') {
            $out = pack('C C x10', $next, 1) . $out;

        } else {
            $out = pack('C C x6', $next, 0) . $out;
        }

        $next = $code;
    }

    return ($next, $out);
}


sub build {
    my ($spec) = @_;
    my @tok = split ' ', $spec;
    my ($fam, $proto, $src, $gt, $dst, @rest) = @tok;
    my (%opt, @patch, $frame);

    croak "bad spec '$spec'"
        unless defined $dst && $gt eq '>' && $fam =~ /^ipv[46]$/;

    for (@rest) {
        if (/^set@(\d+)=(\d+)$/) {
            push @patch, [$1, $2];

        } elsif (/^(\w+)=(.*)$/) {
            $opt{$1} = $2;

        } else {
            croak "bad option '$_' in '$spec'";
        }
    }

    my ($saddr, $sport) = _endpoint($fam, $src);
    my ($daddr, $dport) = _endpoint($fam, $dst);

    if ($fam eq 'ipv4') {
        my ($pnum, $l4) = $proto eq 'frag'
                          ? (PROTO_UDP, '')
                          : _l4($proto, $sport, $dport, \%opt);
        my $tot = 20 + ($proto eq 'frag' ? 8 : length $l4);
        my $ip = pack('C C n n n C C n a4 a4', 0x45, 0, $tot, 0,
                      $opt{off} // 0, 64, $pnum, 0,
                      _addr(AF_INET, $saddr), _addr(AF_INET, $daddr));

        substr($ip, 10, 2) = pack('n', _cksum($ip));

        if (defined $opt{vlan}) {
            $frame = _eth(ETH_P_8021Q) . pack('n n', $opt{vlan}, ETH_P_IP);

        } else {
            $frame = _eth(ETH_P_IP);
        }

        $frame .= $ip . $l4;

    } else {
        my ($pnum, $l4) = _l4($proto, $sport, $dport, \%opt);
        my ($next, $ext) = defined $opt{ext}
                           ? _v6_exts($opt{ext}, $pnum)
                           : ($pnum, '');

        $frame = _eth(ETH_P_IPV6)
                 . pack('C C3 n C C a16 a16', 0x60, 0, 0, 0,
                        length($ext) + length($l4), $next, $opt{hop} // 64,
                        _addr(AF_INET6, $saddr), _addr(AF_INET6, $daddr))
                 . $ext . $l4;
    }

    for my $p (@patch) {
        croak "set\@$p->[0] past end of frame" if $p->[0] >= length $frame;
        substr($frame, $p->[0], 1) = chr $p->[1];
    }

    return $frame;
}


my %sock;

sub send_frame {
    my ($ifname, $frame) = @_;

    unless ($sock{$ifname}) {
        socket(my $s, PF_PACKET, SOCK_RAW, 0)
            or croak "AF_PACKET socket: $!";

        # SIOCGIFINDEX follows this netns; /sys may be the host's sysfs.
        my $ifr = pack('a16 x24', $ifname);

        ioctl($s, SIOCGIFINDEX, $ifr) or croak "no interface $ifname: $!";
        my $ifindex = unpack('x16 i', $ifr);

        # struct sockaddr_ll: family, protocol, ifindex, hatype, pkttype,
        # halen, addr[8].
        $sock{$ifname} = [$s, pack('S n i S C C a8', PF_PACKET, 0, $ifindex,
                                   0, 0, 6, pack('C6', 2, 0, 0, 0, 0, 1))];
    }

    my ($s, $sll) = @{$sock{$ifname}};

    defined send($s, $frame, 0, $sll)
        or croak "send on $ifname: $!";
}

1;
