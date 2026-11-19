# SPDX-License-Identifier: Apache-2.0
# voidgate control socket client: one command per connection, text reply.

package VG::Ctl;

use strict;
use warnings;

use Carp qw(croak);
use IO::Socket::UNIX;
use Socket qw(SOCK_STREAM);

our @EXPORT_OK = qw(ctl stats status);
use Exporter 'import';

our $PATH = '/run/voidgate.sock';


sub ctl {
    my ($line) = @_;
    my $s = IO::Socket::UNIX->new(Type => SOCK_STREAM, Peer => $PATH)
        or croak "connect $PATH: $!";

    print {$s} "$line\n";
    shutdown($s, 1);
    local $/;
    my $reply = <$s>;
    close $s;
    return $reply // '';
}


sub status {
    return ctl('status');
}


sub stats {
    my %t = ctl('stats') =~ /(\w+)=(\S+)/g;

    return \%t;
}

1;
