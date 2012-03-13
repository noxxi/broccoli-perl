#! /usr/bin/env perl

use strict;
use warnings;
use Broccoli;

my $bc = Broccoli->new("127.0.0.1:47758") or die;
my $recv = 0;

$bc->subscribe('test2', sub {
	my ($a,$b,$c,$d,$e,$f,$g,$h,$i,$j) = @_;
	printf "==== atomic a %d ====\n", $recv++;
	print " $a\n";
	print " $b\n";
	printf " %.4f\n",$c;
	print " $d\n";
	print " $e\n";
	print " $f\n";
	print " $g\n";
	print " $h\n";
	print " $i\n";
	print " $j\n";
});

$bc->subscribe('test4', sub {
	my $r = shift;
	printf "==== record %d ====\n", $recv++;
	print " $r\n";
	print " $r->{a}\n";
	print " $r->{b}\n";
});

$bc->connect;


$bc->send("test1", 
    bc_int(-10), 
    bc_count(2), 
    bc_time(current_time()), 
    bc_interval(120), 
    bc_bool(0), 
    bc_double(1.5), 
    bc_string("Servus"), 
    bc_port("5555/tcp"), 
    bc_ipaddr("6.7.6.5"), 
    bc_subnet("192.168.0.0/16")
);

$recv = 0;
for($recv = 0;$recv<2; $bc->processInput()) {
    sleep(1);
}

my $rec = record_type(qw(a:int b:ipaddr));
my $r = $rec->new( a => 42, b => '6.6.7.7');
$bc->send("test3", $r);
    
$recv = 0;
for($recv = 0;$recv<2; $bc->processInput()) {
    sleep(1);
}

my $opt_record = record_type(qw(one:int a:int b:ipaddr c:string d:string));
$r = $opt_record->new;
$r->{a} = 13;
$r->{c} = "helloworld";
$r->{b} = "3.4.5.6";
$bc->send("test5", $r)
