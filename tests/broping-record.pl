#! /usr/bin/env perl
#
# Use with broccoli/test/broping-record.bro.

use strict;
use warnings;
use Broccoli;

my $ping_data = record_type(qw(seq:count src_time:time));
my $bc = Broccoli->new("127.0.0.1:47758");

$bc->subscribe('pong', sub {
	my $r = shift;
    printf "pong event: seq=%i, time=%f/%f \n", 
		$r->{seq},
        $r->{dst_time} - $r->{src_time}, 
		current_time() - $r->{src_time}
});

$bc->connect;
for(my $seq=1;1;$seq++) {
	$bc->send('ping', $ping_data->new(
		seq => $seq,
		src_time => current_time(),
	));
    sleep(1);
}
    


