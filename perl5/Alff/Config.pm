#!/usr/bin/perl -w
#
# Alff::Config
#
# Config helpers for the RBM firewall framekwork
#
# Maximilian Wilhelm <max@rfc2324.org>
#  -- Thu, 27 Apr 2006 15:20:39 +0200
#

package Alff::Config;

my $VERSION="1.0";

use strict;
use Alff::Main;
use XML::Simple;

my $default_configfile = "/etc/alff/alff.conf";


##
# Little bit of magic to simplify debugging
sub _options(@) { #{{{
	my %ret = @_;

	if ( $ret{debug} ) {
		foreach my $opt (keys %ret) {
			print STDERR "Alff::Config->_options: $opt => $ret{$opt}\n";
		}
	}

	return \%ret;
} #}}}

##
# Constructor
sub new { #{{{
	my $self = shift;
	my $class = ref($self) || $self;

	# Put arguments into ref(hashtable);
	my $args = &_options ;

	my $configfile = $args->{configfile} || $default_configfile;
	my $debug = $args->{debug} || 0;

	my $alff = Alff::Main->new();

	my $obj = bless { 
		alff => $alff,
		args => $args,
		configfile => $configfile,
		debug => $debug,
		}, $class;
	
	
	my $config = $obj->loadConfig( $configfile  );

	$obj->{config} = $config;

	$obj->checkConfig unless ( $args->{nocheck} );
	$obj->sanitizeSecurityClasses;

	return $obj;
} #}}}

##
# Load the configuration from given $configfile
sub loadConfig($) { #{{{
	my $self = shift;
	my $configfile = shift;

	my $config;

	# Load the configuration
	if ( ! -f $configfile ) {
		print STDERR "Error: Configfile $configfile does not exist.\n";
		return undef;
	}

	# Parse the configuration
	$config = XML::Simple::XMLin( $configfile, NormalizeSpace => 2 )
			or return undef;

	if ( $self->{debug} ) {
		print STDERR "Found the following vlans: " . join(", ", sort keys %{$config->{vlan}}) . "\n";
	}

	return $config;
} #}}}

##
# Check the configuration
sub checkConfig() { #{{{
	my $self = shift;

	# Check the firewall type #{{{
	if ( defined $self->{config}->{options}->{fw_type} ) {
		my $fw_type = $self->{config}->{options}->{fw_type};

		if ( $fw_type eq "router" ) {
			
		}
		elsif( $fw_type eq "bridge" ) {
			print STDERR "The bridging mode is not supported by alff atm... Sorry!\n";
			exit 1
		}
		else {
			print STDERR "Error: fw_type has to be either \"router\" or \"bridge\"!\n";
		}
	}
	else {
		print STDERR "Error: You did not specify a fw_type in $self->{configfile}\n";
		exit 1;
	}
	#}}}

	# Check the default_chain_policy #{{{
	if ( defined $self->{config}->{options}->{default_chain_policy} ) {

		my $policy = $self->{config}->{options}->{default_chain_policy};

		# Check if default_chain_policy is *not* on of {ACCEPT, DROP, REJECT, LOG}, and
		# have a detailed look at the policy, if not.
		# (Don't check end-of-word at REJECT and LOG because of possible options)
		if ( ! ( $policy =~ m/^ACCEPT$|^DROP$|^LOG|^REJECT/ ) ) {
			if ( ! $self->{alff}->chain_exists( $policy ) ) {
				print STDERR "Error: Invalid default_chain_policy $policy, defaulting to REJECT\n";
				$self->{config}->{options}->{default_chain_policy} = "REJECT";
			}
		} 
	} else {
		print STDERR "Warning: default_chain_policy not specified in config, defaulting to REJECT\n";	
		$self->{config}->{options}->{default_chain_policy} = "REJECT";
	}

	print STDERR "INFO: default_chain_policy is set to \"$self->{config}->{options}->{default_chain_policy}\"\n" if ( $self->{debug} );

	#}}}

} #}}}

##
# Collect and sanitize securityClasses
sub sanitizeSecurityClasses() { #{{{
	my $self = shift;
	my @vlans = $self->getVlanList();
	my %allSecurityClasses;

	foreach my $vlan_id ( @vlans ) {
		my $vlan_ref = $self->{config}->{vlan}->{$vlan_id};
		my @securityClasses = ();

		# Check for standard security classes
		for my $stdSecClass ( "filtered", "trusted" ) {
			if ( defined $vlan_ref->{$stdSecClass} ) {
				if ( $vlan_ref->{$stdSecClass} eq "yes" ) {
					push @securityClasses, $stdSecClass
				}
			}
		}

		# Check for additional security_classes
		if ( defined $vlan_ref->{security_class} ) {
			# There maybe a list of additional security classes
			if ( ref ( $vlan_ref->{security_class} )  ) {
				push @securityClasses, @{$vlan_ref->{security_class}};
			} else {
				push @securityClasses, $vlan_ref->{security_class};
			}
		}

		# Store reference to all security classes of this vlan in the vlan object
		$vlan_ref->{securityClasses} = \@securityClasses;

		# Store all security classes of this vlan in the global security class list
		foreach my $vlanSecClass ( @securityClasses ) {
			$allSecurityClasses{$vlanSecClass} = 1;
		}
	}

	my @allSecurityClassesList = keys %allSecurityClasses;
	$self->{config}->{allSecurityClasses} = \@allSecurityClassesList;
}
#}}}

################################################################################
#			    Basic config options			       #
################################################################################

##
# Get the default chain policy
sub getDefaultChainPolicy() { #{{{
	my $self = shift;

	return $self->{config}->{options}->{default_chain_policy};
} #}}}

##
# Get a list of the configured DHCP servers
sub getDHCPServers() { #{{{
	my $self = shift;

	my @dhcp_servers = ref($self->{config}->{options}->{dhcp_server}) ? @{$self->{config}->{options}->{dhcp_server}} : ( $self->{config}->{options}->{dhcp_server} );

	return @dhcp_servers;
} #}}}

##
# Get option $option from the configuration
sub getOption($) { #{{{
	my $self = shift;
	my $conf_opt = shift;

	return $self->{config}->{options}->{$conf_opt};
} #}}}

# Get a list of all known securityClasses
sub getSecurityClasses() { #{{{
	my $self = shift;

	return sort @{$self->{config}->{allSecurityClasses}};
} #}}}

################################################################################
#				Vlan handling				       #
################################################################################

##
# Return a list of known vlans
sub getVlanList() { #{{{
	my $self = shift;

	return sort keys %{$self->{config}->{vlan}};
} #}}}

##
# Return a list of all vlans of the specified security class
sub getVlansOfSecurityClass($) { #{{{
	my $self = shift;
	my $securityClass = shift;
	my @allSecurityClasses = @{$self->{config}->{allSecurityClasses}};

	# Check if the given $securityClass is valid
	return ( ) unless grep { /^$securityClass$/ } @allSecurityClasses;

	my @allvlans = $self->getVlanList;
	my @vlans = ( );

	foreach my $vlanId ( @allvlans ) {
		my $vlan_ref = $self->{config}->{vlan}->{$vlanId};
		if ( grep { /^$securityClass$/ } @{$vlan_ref->{securityClasses}} ) {
			push @vlans, $vlanId;
		}
	}

	return @vlans;
} #}}}

##
# Wrapper for getVlansOfSecurityClass for filtered vlans
sub getFilteredVlans() { #{{{
	my $self = shift;
	return $self->getVlansOfSecurityClass( "filtered" );
} #}}}

##
# Wrapper for getVlansOfSecurityClass for trusted vlans
sub getTrustedVlans() { #{{{
	my $self = shift;
	return $self->getVlansOfSecurityClass( "trusted" );
} #}}}

##
# Return 1 if given vlan is filtered, 0 else
sub isFilteredVlan($) { # $vlan_id -> {0, 1} {{{
	my $self = shift;

	my $vlan_id = shift;
	my $vlan_ref = $self->{config}->{vlan}->{$vlan_id};

	# If $vlan_id is not configured, it´s surely not filtered...
	return 0 unless ( defined  $vlan_ref );

	# If $vlan_id exists, but <filtered> was not mentioned, it´s not filtered.
	return 0 unless ( exists $vlan_ref->{filtered} );

	# OK, someone configured something. Is it filtered?
	return $vlan_ref->{filtered} eq "yes";
} # }}}

##
# return the interface name for vlan $vlan, "" if unset 
sub getVlanInterface($) { # $vlan_id -> string  {{{
	my $self = shift;

	my $vlan_id = shift;
	my $vlan_ref = $self->{config}->{vlan}->{$vlan_id};

	# If $vlan_id is not configured, there surely is no interface for it
	return "" unless ( defined $vlan_ref );

	# $vlan_id exists, but <interface> is unset...
	return "" unless ( exists $vlan_ref->{interface} );
	
	# Ok, <interface> is set, return it.
	return $vlan_ref->{interface};
} #}}}

##
# return the list of networks for the given vlan
sub getVlanNetworks($) { # $vlan_id -> ( list of networks ) {{{
	my $self = shift;

	my $vlan_id = shift;
	my $vlan_ref = $self->{config}->{vlan}->{$vlan_id};

	# If () is not configured, there surely are no networks for it
	return () unless ( defined $vlan_ref );

	# At least one <network> tag has to be there because DTD requires it.
	if ( ref( $vlan_ref->{network})  ) {
		# Ok, it is already a list
		return @{$vlan_ref->{network}};
	} else {
		# Create a pseudo list, with just one element
		return ( $vlan_ref->{network} );
	}
} #}}}

################################################################################
#				Machine handling			       #
################################################################################

##
# Get a list of all known machine IDs
sub getMachineIds() { #{{{
	my $self = shift;

	return sort keys %{$self->{config}->{machine}};
} #}}}

##
# Check wether the given machine ID is valid.
sub isValidMachineID { #{{{
	my $self = shift;
	my $machine_ID = shift;

	return defined $self->{config}->{machine}->{$machine_ID};
} #}}}

##
# Get the hostname for machine ID
sub getMachineHostname($) { #{{{
	my $self = shift;
	my $machine_id = shift;

	return $self->isValidMachineID( $machine_id ) ? $machine_hostname = $self->{config}->{machine}->{$machine_id}->{hostname} : undef;
} #}}}

##
# Get the IP for the machine with the given ID
sub getMachineIP($) { #{{{
	my $self = shift;
	my $machine_id = shift;

	return $self->isValidMachineID( $machine_id ) ? $self->{config}->{machine}->{$machine_id}->{ip} : undef;
} #}}}

1;
# vim:foldmethod=marker
