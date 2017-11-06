#!/usr/bin/env perl
use strict;
use warnings;

use NetPacket::Ethernet ();
use NetPacket::IP ();
use NetPacket::TCP ();
use IO::Async::Stream ();
use IO::Async::Loop::EV ();
use IO::Async::Function ();
use Future::Utils qw/repeat/;
use File::Slurp qw/write_file/;
use Data::Dumper qw/Dumper/;
use Log::Log4perl qw(:easy);
Log::Log4perl->easy_init({ level => $DEBUG, layout => "[%P] %p: %m%n" });

our $N;
our $Strip;
our $Filter;
our $Header = {};
our $Worker = IO::Async::Function->new(
	code => sub {
		my $ip = NetPacket::IP->decode($_[0]);
		#my $tcp = NetPacket::TCP->decode($ip->{data});
		my $res = {
			src_ip => $ip->{src_ip},
			dest_ip => $ip->{dest_ip},
			#src_port => $tcp->{src_port},
			#dest_port => $tcp->{dest_port},
		};
		#write_file('tcpdump_logs.txt', {append => 1}, Dumper($res));
		DEBUG Dumper($res);
		return 1;
	},
	max_workers => 1,
	min_workers => 1,
);

my $loop = IO::Async::Loop::EV->new;
$loop->add($Worker);

my $stream = IO::Async::Stream->new(
	read_handle  => \*STDIN,
	on_read => sub { 0 },
);
$loop->add($stream);


#$Filter = sub { # NOTE before any stripping
#	use bytes;
#	#14 ethernet header +
#	#20 ip header +
#	#14th octet of tcp header
#	#= 48
#	my $offset = 48;
#	length $_[0] >= $offset
#		and (unpack "C$offset", $_[0])[-1] & 0b10; # SYN
#};

$Strip = sub {
	#NetPacket::IP::strip( NetPacket::Ethernet::strip($_[0]) );
	#NetPacket::Ethernet::strip($_[0]);

	# or just use unpack:
	$_[0] = unpack 'x14a*', $_[0];
};

DEBUG "start!";

$stream
#my @res = $stream
->read_exactly(4)
->then(sub {
		my ($magic, $eof) = @_;
		if ($eof) {
			return Future->fail("invalid file");
		}
		return determine_endianness($stream, $magic);
	})
->then(sub { $_[0]->read_exactly(20); })
->then(sub {
		my ($f_head, $eof) = @_;
		if ($eof) {
			return Future->fail("invalid file");
		}
		return parse_per_file_h($stream, $f_head);
	})
->then(\&parse_packets)
->then(sub {
		# NOTE is there a better way to do this?
		return Future->wait_all( values %{$Worker->{IO_Async_Notifier__futures}} );
	})
->else(sub {
		warn $_[0];
		return Future->done;
	})
->get;

DEBUG "fin!";

sub determine_endianness {
	my ($stream, $magic) = @_;
	DEBUG "determine_endianness";
	$N = unpack('V', $magic) == 0xa1b2c3d4 ? 'v' : 'n';
	return Future->done($stream);
}

sub parse_per_file_h {
	my ($stream, $f_head) = @_;
	DEBUG "parse_per_file_h";
	my @keys = qw/maj_v min_v tz_off tz_acc snap_len link_layer_h_type/;
	@{ $Header }{@keys} = unpack lc($N) x 2 . uc($N) x 4, $f_head;
	return Future->done($stream);
}

sub parse_packets {
	DEBUG "parse_packets";
	my ($stream) = @_;
	my ($p, $eof);
	my $packet_header = {};
	my @keys = qw/ts_seconds ts_micros cap_len real_len/;

	return repeat {

		$stream
		->read_exactly(16)
		->then(sub {
				($p, $eof) = @_;

				$eof and return Future->fail('eof');

				@{ $packet_header }{@keys} = unpack uc($N) x 4, $p;

				return $stream->read_exactly($packet_header->{cap_len});
			})
		->then(sub {
				($p, $eof) = @_;

				$Filter->($p) or return Future->done() if $Filter;
				$p = $Strip->($p) if $Strip;

				$Worker->call( args => [ $p ], on_result => sub { 1 } );

				return Future->done;
			})
		->else(sub { DEBUG "eof reached"; Future->done; });

	} until => sub { $eof };
}
