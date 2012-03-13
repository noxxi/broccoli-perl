#! /usr/bin/env perl

use strict;
use warnings;
use Broccoli;
use IO::Select;

my $bc = Broccoli->new("127.0.0.1:47758") or die;

$bc->subscribe('http_request', sub {
	my ($c,$method,$uri,$uri_o,$version) = @_;
	print "REQ($c->{uid}) $method $uri_o HTTP/$version\n";
});

$bc->subscribe('http_reply', sub {
	my ($c,$version,$code,$reason) = @_;
	print "RSP($c->{uid}) HTTP/$version $code $reason\n";
});

# XXX use http_all_headers
# but we need to implement table type first
$bc->subscribe('http_header', sub {
	my ($c,$is_orig,$key,$val) = @_;
	print "HDR($c->{uid},$is_orig) $key: $val\n";
});

if(0) {
$bc->subscribe('http_entity_data', sub {
	my ($c,$is_orig,$size,$data) = @_;
	print "DATA($c->{uid},$is_orig) $data\n";
});
}

$bc->connect;
my $sel = IO::Select->new($bc->fd);
while (1) {
	$bc->processInput() && redo;   # redo if more events
	$sel->can_read(10);
}

