
use strict;
use warnings;

package Broccoli;
use base 'Exporter';
use vars '@EXPORT';
use Carp;

use broccoli_intern;
broccoli_intern::bro_init(undef);

use constant {
	BRO_CFLAG_NONE => 0,
	BRO_CFLAG_RECONNECT => (1 << 0),
	BRO_CFLAG_ALWAYS_QUEUE => (1 << 1),
	BRO_CFLAG_SHAREABLE => (1 << 2),
	BRO_CFLAG_DONTCACHE => (1 << 3),
	BRO_CFLAG_YIELD => (1 << 4),
	BRO_CFLAG_CACHE => (1 << 5),
};


BEGIN {
	@EXPORT = qw(
		current_time 
		record_type
		BRO_CFLAG_NONE BRO_CFLAG_RECONNECT BRO_CFLAG_ALWAYS_QUEUE
		BRO_CFLAG_SHAREABLE BRO_CFLAG_DONTCACHE BRO_CFLAG_YIELD
		BRO_CFLAG_CACHE
	);
	for my $type ( qw(
		int double string count time interval bool enum port ipaddr subnet
		)) {
		eval "sub Broccoli::bc_$type { Broccoli::$type->new(shift) }";
		push @EXPORT,"bc_$type";
	}
}


# shortcut
sub new {
	shift;
	return Broccoli::Connection->new(@_)
}

sub current_time {
    return broccoli_intern::bro_util_current_time()
}


##### create record type
{
	my $id = 0;
	sub record_type {
		my %f2t;
		for my $f (@_) {
			my ($name,$type) = ref($f) ? @$f : split(':',$f,2);
			$f2t{$name} = $type;
		}

		$id++;
		my $class = "Broccoli::record::r$id";
		no strict 'refs';
		*{"${class}::ISA"} = ['Broccoli::record'];
		*{"${class}::field2type"} = \%f2t;
		return $class;
	}
}

package Broccoli::Connection;
use fields qw(bc destination);
use Scalar::Util 'looks_like_number';
use Carp;

##### Connection class which capsulates a Broccoli connection.
# Connection to dst given as string "host:port"
sub new {
	my ($class,$dst,$broclass,$flags) = @_;
	$flags ||= Broccoli::BRO_CFLAG_RECONNECT | Broccoli::BRO_CFLAG_ALWAYS_QUEUE;

	my $self = fields::new($class);
	$self->{bc} = broccoli_intern::bro_conn_new_str($dst,$flags)
		or croak "cannot init Broccoli connection handle";
	$self->{destination} = $dst;

	broccoli_intern::bro_conn_set_class($self->{bc},$broclass)
		if defined $broclass;

	return $self;
}

# If the instance was created with ! connect, this will trigger the connect.
sub connect {
	my $self = shift;
	broccoli_intern::bro_conn_connect($self->{bc})
		or croak "cannot connect to $self->{destination}"
}

# Hand control to Broccoli's I/O loop.
# Returns true if the send queue is non-empty.
sub processInput {
	my $self = shift;
	broccoli_intern::bro_conn_process_input($self->{bc});
	return broccoli_intern::bro_event_queue_length($self->{bc})>0;
}

# return file handle for select
sub fd {
	my $self = shift;
	return broccoli_intern::bro_conn_get_fd($self->{bc})
}

# Send an event of name with args.
sub send {
	my ($self,$name,@args) = @_;
	my $ev = broccoli_intern::bro_event_new($name);
	for my $arg (@args) {
		broccoli_intern::bro_event_add_val($ev,$arg);
	}
	broccoli_intern::bro_event_send($self->{bc},$ev);
	broccoli_intern::bro_event_free($ev);
	$self->processInput;
}

# Explicit subscribe
sub subscribe {
	my ($self,$event_name,$callback) = @_;
	broccoli_intern::bro_event_registry_add_compact($self->{bc},$event_name,$callback);
}



package Broccoli::int;
sub new { my ($class,$val) = @_; bless \$val,$class }

package Broccoli::double;
sub new { my ($class,$val) = @_; bless \$val,$class }

package Broccoli::string;
sub new { my ($class,$val) = @_; bless \$val,$class }

package Broccoli::bool;
sub new { my ($class,$val) = @_; bless \$val,$class }

package Broccoli::count;
sub new { my ($class,$val) = @_; bless \$val,$class }

package Broccoli::time;
sub new { my ($class,$val) = @_; bless \$val,$class }

package Broccoli::interval;
sub new { my ($class,$val) = @_; bless \$val,$class }

package Broccoli::ipaddr;
use Socket;
use Carp;
sub new { 
	my ($class,$val) = @_; 
	$val = inet_aton($val) if length($val) != 4;
	$val or croak "invalid @_";
	bless \$val,$class;
}
use overload '""' => sub { 
	my $self = shift;
	inet_ntoa($$self) 
};


package Broccoli::enum;
sub new { 
	my ($class,$val,$name) = @_; 
	$name = $1 if ! defined $name && $val =~s{/(.+)}{};
	bless [$val,$name],$class 
}
use overload '""' => sub { 
	my $self = shift;
	"$self->[0]/$self->[1]"
};

package Broccoli::port;
use Carp;
sub new { 
	my ($class,$port,$proto) = @_; 
	$proto = $1 if ! defined $proto && $port =~s{/(.+)}{};
	$proto = getprotobyname($proto) unless $proto =~m{^\d+$};
	$port = getservbyname($port,$proto) unless $port =~m{^\d+$};
	croak "invalid @_" if ! $port || ! $proto;
	bless [$port,$proto],$class 
}
use overload '""' => sub { 
	my $self = shift; 
	my $proto = getprotobynumber($self->[1]);
	"$self->[0]/$proto"
};

package Broccoli::subnet;
use Socket;
use Carp;
sub new { 
	my ($class,$net,$mask) = @_; 
	$mask = $1 if ! defined $mask && $net =~s{/(.+)}{};
	$net = inet_aton($net) if length($net) != 4;
	$mask||= 0;
	croak "invalid @_" unless $mask>=0 and $mask<=32;
	bless [$net,$mask],$class 
}
use overload '""' => sub { 
	my $self = shift; 
	inet_ntoa($self->[0])."/$self->[1]" 
};


package Broccoli::record;
sub new {
	my ($class,%data) = @_;
	if (my $c = ref($class)) {
		# make new like this, copy internal field2type map if exists
		my $f2t = $c->{"\0f2t"};
		return $c->new( $f2t ? ( "\0f2t" => $f2t ):(), %data);
	}
	return bless \%data,$class;
}

use overload '""' => sub {
	my $self = shift;
	return '[ '.join(', ', map { $_ =~m{^\0} ? ():("$_:$self->{$_}") } keys %$self ).' ]';
};

1;
__END__

=head1 NAME 

Broccoli - Perl bindings to communication interface of IDS Bro

=head1 SYNOPSIS

	my $bc = Broccoli->new('host:port');
	$bc->subscribe('pong', sub {
		my ($seq,$record) = shift;
		print "seq=$seq r.a=$record->{a}...\n";
	});
	$bc->connect;
	my $rec = record_type(qw(a:int i:ipaddr));
	$bc->send('ping',
		bc_count(1),
		bc_time(current_time()),
		$rec->new( a => 4, b => '10.0.3.4' )
	);

=head1 DESCRIPTION

...

=head1 AUTHOR

Steffen Ullrich, GeNUA mbH
