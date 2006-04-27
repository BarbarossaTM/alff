#!/usr/bin/perl -w
#
# Fwrbm
#
# Basic module for the RBM Firewall framework
#
# Maximilian Wilhelm <max@rfc2324.org>
#  -- Thu, 27 Apr 2006 15:18:13 +0200
#
package Fwrbm::Main;

use strict;

sub new() {
	my $self = shift;
	my $class = ref($self) || $self;

	bless { debug => 0,
		dry_run => 0
		}, $class;
}

##
# system-wrapper with error checking
sub run_cmd(@) { #{{{
	my $self = shift;
	my $cmd = shift;
	my @args = shift || ();

	if ( $self->{debug} ) {
		if ( @args ) {
			print STDERR "run \"$cmd\" with args " . join(" ", @args ) . "\n";
		} else {
			print STDERR "run \"$cmd\"\n";
			
		}
	}
	
	return 0 if ( $self->{dry_run} );

	my $ret = system( $cmd, @args );

	if ( $ret == -1 ) {
		printf "Error: Failed to execute %s with args %s\"",
			$cmd, join(" ", @args);
	}
	elsif ( $? & 127 ) {
		printf "Error while executing %s, child died with signal %d, %s coredump\n",
			$cmd, ($? & 127), ($? & 128) ? 'with' :  'without';
	}
	elsif ( $? ) {
		printf "Error while executing %s with args %s, child exited with value %d\n",
			$cmd, join(" ", @args), $? >> 8;
	}

	return $ret;
} #}}}

1;
# vim:foldmethod=marker:
