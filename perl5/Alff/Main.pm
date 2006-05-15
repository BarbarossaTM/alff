#!/usr/bin/perl -w
#
# Alff
#
# Basic module for the RBM Firewall framework
#
# Maximilian Wilhelm <max@rfc2324.org>
#  -- Thu, 27 Apr 2006 15:18:13 +0200
#
package Alff::Main;

$VERSION="1.0";

use strict;
use File::Basename;
use IO::Handle;

##
# Little bit of magic to simplify debugging
sub _options(@) { #{{{
        my %ret = @_;

        if ( $ret{debug} ) {
                foreach my $opt (keys %ret) {
                        print STDERR "Alff::Main->_options: $opt => $ret{$opt}\n";
                }
        }

        return \%ret;
} #}}}

##
# Constructor
sub new() { #{{{
	my $self = shift;
	my $class = ref($self) || $self;

	my $args = &_options;

	my $debug = $args->{debug} || 0;
	my $cache_dir_chains = $args->{cache_dir_chains} || "/var/cache/alff/chains";

	my $fh = IO::Handle->new();
	$fh->fdopen( 3, "w" );			# open fd 3 for writing

	bless { debug => $debug,
		output_fh => $fh,
		cache_dir_chains => $cache_dir_chains,
		}, $class;
} #}}}

##
# Write out the content of the given file
sub write_filecontent($) { #{{{
	my $self = shift;
	my $file = shift;
	my $output_fh = $self->{output_fh};

	unless ( open ( FILE, "<$file" ) ) {
		print STDERR "Error: Could not open file $file for reading...\n";
		return 0;
	}

	while ( my $line = <FILE> ) {
		print $output_fh "$line";
	}
	close( FILE );

	return 1;
} #}}}

##
# Write out the given command line to fd3
sub write_cmd($) { #{{{
	my $self = shift;
	my $cmd = shift;
	my $output_fh = $self->{output_fh};

	print $output_fh "$cmd\n";
} #}}}

##
# Create a chain and make it known to alff
sub create_chain($) { #{{{
	my $self = shift;
	my $chain = shift;
	my $table = shift || "filter";

	my $output_fh = $self->{output_fh};

	unless ( $self->chain_exists( $chain, $table ) ) {
		my $chain_file = "$self->{cache_dir_chains}/$table/$chain";
		open ( CHAINFILE, ">$chain_file" )
			or die "Cannot create file $chain in $self->{cache_dir_chains}/$table";
		print CHAINFILE "exists";
		close( CHAINFILE );
	}

	print $output_fh 
"if ! iptables -t $table -F $chain >/dev/null 2>/dev/null; then
iptables -t $table -N $chain
fi\n";

} #}}}

##
# Check if chain $arg1 exists in table ($arg2 || filter)
sub chain_exists($) { #{{{
	my $self = shift;
	my $chain = shift;
	my $table = shift || "filter";

	my $chain_file = "$self->{cache_dir_chains}/$table/$chain";

	return ( -f $chain_file );
}

1;
# vim:foldmethod=marker:
