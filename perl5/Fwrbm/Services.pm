#!/usr/bin/perl -w
#
# Fwrbm::Services
#
# Service handling routines for the RBM firewall framework
#
# Maximilian Wilhelm <max@rfc2324.org>
#  -- Fri, 28 Apr 2006 15:44:02 +0200
#

package Fwrbm::Services;

$VERSION = "1.0";
$AUTHOR='Maximilian Wilhelm <max@rfc2324.org>';

use strict;
use Fwrbm::Config;
use Fwrbm::Main;

my $debug = 0;
my $dry_run = 0;

##
# Create new instance
sub new { #{{{
	my $self = shift;
	my $class = ref($self) || $self;

	my $config = Fwrbm::Config->new( debug => $debug );
	my $fwrbm = Fwrbm::Main->new( debug => $debug, dry_run => $dry_run );

	my $obj = bless {
		config => $config,
		fwrbm_main => $fwrbm
		}, $class;

	return $obj;
} #}}}

##
# Hook in chains to branch traffic from networks of the given security class
# into the chain allowServicesFrom${securityClass}Nets
sub allowServiceFromNetworksOfSecurityClass($) { #{{{
	my $self = shift;
	my $securityClass = shift;

	my $config = $self->{config};
	my $main = $self->{fwrbm_main};

	my $chain = "allowServicesFrom" . ucfirst ${securityClass} . "Nets";
	my @vlans = $config->getVlansOfSecurityClass( $securityClass );

	if ( scalar( @vlans ) > 0 ) {
		# Check if chain exists...
		if ( system("/sbin/iptables -L $chain -n >/dev/null 2>/dev/null") ) {
			print STDERR "Error: There is no service chain for security class $securityClass\n";
			return;
		}

		print " * Allowing access to services configured to be available from networks of sec. class $securityClass... ";
		foreach my $vlan ( @vlans ) {
			# Could be multiple networks
			my @networks = $config->getVlanNetworks( $vlan );

			foreach my $network ( @networks ) { 
				$main->run_cmd("/sbin/iptables -A FORWARD -s ${network} -j $chain");
			}
			print ".";

		}
		print " done.\n";
	}
	else {
		print STDERR "Attention: There are not networks of security class $securityClass, staying cool.\n";
	}
} #}}}

##
# Hook in a chain to branch packet processing into a chain where all world open
# services are hooked in.
sub allowWorldOpenServices() { #{{{
	my $self = shift;
	my $main = $self->{fwrbm_main};

	print " * Creating rule to allow access to services configured to be world-wide available...";
	print $main->run_cmd("/sbin/iptables -A FORWARD -j allowWorldOpenServices") ? "done.\n" : "FAILED\n";
} #}}}

1;
# vim:foldmethod=marker
