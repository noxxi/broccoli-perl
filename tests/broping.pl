#! /usr/bin/env perl
#
# Use with broccoli/test/broping.bro.

use strict;
use warnings;
use Broccoli;

my $bc = Broccoli->new("127.0.0.1:47758") or die $!;
$bc->subscribe('pong',sub {
	my ($src_time,$dst_time,$seq) = @_;
    printf "pong event: seq=%i, time=%f/%f\n", 
		$seq, 
		$dst_time - $src_time, 
		current_time() - $src_time
});
$bc->connect or die $!;


for( my $seq = 1;1;$seq++ ) {
    $bc->send("ping", bc_time(current_time()), bc_count($seq));
    sleep(1);
}
    


