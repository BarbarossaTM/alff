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

$VERSION="1.0";
$AUTHOR='Maximilian Wilhelm <max@rfc2324.org>';

use strict;

##
# Little bit of magic to simplify debugging
sub _options(@) { #{{{
        my %ret = @_;

        if ( $ret{debug} ) {
                foreach my $opt (keys %ret) {
                        print STDERR "Fwrbm::Config->_options: $opt => $ret{$opt}\n";
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
	my $dry_run = $args->{dry_run} || 0;

	bless { debug => $debug,
		dry_run => $dry_run,
		}, $class;
} #}}}

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
		printf STDERR "Error: Failed to execute %s with args %s\"",
			$cmd, join(" ", @args);
	}
	elsif ( $ret & 127 ) {
		printf STDERR "Error while executing %s, child died with signal %d, %s coredump\n",
			$cmd, ($? & 127), ($? & 128) ? 'with' :  'without';
	}
	elsif ( $ret ) {
		printf STDERR "Error while executing %s with args %s, child exited with value %d\n",
			$cmd, join(" ", @args), $? >> 8;
	}

	# Be aware of the different true/false idea between shell and perl
	# Exit code 0 -> 1 in perl and vice versa.
	return $ret == 0 ? 1 : 0 ;
} #}}}

1;
# vim:foldmethod=marker:
