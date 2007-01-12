#!/usr/bin/perl -w
#
# Alff::Helper
#
# Hepler functions for Alff plugins and others
#
# Maximilian Wilhelm <max@rfc2324.org>
#  -- Fri, 12 Jan 2007 20:57:30 +0100
#

package Alff::Helper;

$VERSION = "0.1";

use strict;

# For the ones - like me - who can´t remember what´s true and false
my $true  = 1;
my $false = 0;

##
# Little bit of magic to simplify debugging
sub _options(@) { #{{{
        my %ret = @_;

        if ( $ret{debug} ) {
                foreach my $opt (keys %ret) {
                        print STDERR "Alff::Helper->_options: $opt => $ret{$opt}\n";
                }
        }

        return \%ret;
} #}}}

##
# Create new instance
# 
sub new { #{{{
	my $self = shift;
	my $class = ref($self) || $self;

	# Get options
	my $args = &_options;

	# Default options, if unset
	my $debug = $args->{debug} || 0;

	my $obj = bless {
		debug => $debug,
		}, $class;

	return $obj;
} #}}}

##
# Check if $_ is a directory or a link to a directory
sub isdir($) { #{{{
	my $dir = shift;

	return 1 if ( -d $dir );

	if ( -l $dir ) {
		$dir = readlink $dir
			or die "Error: Could not 'readlink $dir'.\n";

		return ( -d $dir );
	}

	return 0;
} #}}}

1;

# vim:foldmethod=marker

