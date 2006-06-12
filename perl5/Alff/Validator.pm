#!/usr/bin/perl -w
#
# Alff::Validator
#
# Validation tools provided / used by Alff
#
# Maximilian Wilhelm <max@rfc2324.org>
#  -- Mon, 12 Jun 2006 18:35:29 +0200
#

package Alff::Validator;

$VERSION = "1.0";

use strict;

##
# Little bit of magic to simplify debugging
sub _options(@) { #{{{
        my %ret = @_;

        if ( $ret{debug} ) {
                foreach my $opt (keys %ret) {
                        print STDERR "Alff::Validator->_options: $opt => $ret{$opt}\n";
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

	# Create instances for used objects

	my $obj = bless {
		debug => $debug,
		}, $class;

	return $obj;
} #}}}

##
# validate_port( $port )
sub validate_port($) { #{{{
	my $self = shift;
	my $port_spec = shift;		# the port

	if ( $port_spec =~ m/(\d+)\/(tcp|udp)/ ) {
		if ( $1 >= 0 and $1 <= 65535 ) {
			return 1;
		}
	}

	return 0;

} #}}}

1;
# vim:foldmethod=marker
