#!/usr/bin/perl -w
#
# Alff::Services
#
# Service handling routines for the RBM firewall framework
#
# Maximilian Wilhelm <max@rfc2324.org>
#  -- Fri, 28 Apr 2006 15:44:02 +0200
#

package Alff::Service;

$VERSION = "1.0";

use strict;
use Alff::Config;
use Alff::Main;
use Alff::Validator;

##
# Little bit of magic to simplify debugging
sub _options(@) { #{{{
        my %ret = @_;

        if ( $ret{debug} ) {
                foreach my $opt (keys %ret) {
                        print STDERR "Alff::Services->_options: $opt => $ret{$opt}\n";
                }
        }

        return \%ret;
} #}}}

##
# Create new instance
# 
# Available options:
#  * debug -> Print degub information? (default: 0)
#  * services_d -> Path to service configuration dir (default: /etc/alff/services.d)
#
sub new { #{{{
	my $self = shift;
	my $class = ref($self) || $self;

	# Get options
	my $args = &_options;

	# Default options, if unset
	my $debug = $args->{debug} || 0;
	my $services_d = $args->{services_d} || "/etc/alff/services.d";

	# Create instances for used objects
	my $config = Alff::Config->new( debug => $debug );
	my $alff_main = $args->{alff_main} || Alff::Main->new( debug => $debug );
	my $alff_validator = $args->{alff_validator} || Alff::Validator->new( debug => $debug );

	my $obj = bless {
		alff_main => $alff_main,
		alff_validator => $alff_validator,
		config => $config,
		debug => $debug,
		services_d => $services_d,
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
	my $main = $self->{alff_main};

	my $chain = "allowServicesFrom" . ucfirst ${securityClass} . "Nets";
	my @vlans = $config->getVlansOfSecurityClass( $securityClass );

	if ( scalar( @vlans ) > 0 ) {
		# Check if chain exists...
		if ( ! $main->chain_exists( $chain, "filter" ) ) {
			print STDERR "Error: There is no service chain for security class $securityClass\n";
			return;
		}

		print " * Allowing access to services configured to be available from networks of sec. class $securityClass... ";
		foreach my $vlan ( @vlans ) {
			# Could be multiple networks
			my @networks = $config->getVlanNetworks( $vlan );
			# Maybe there is an interface specified
			my @interfaces = $config->getVlanInterfaces( $vlan );

			foreach my $interface (@interfaces)
			{
				my $chain_rule = "iptables -A FORWARD ";
				if ($interface) {
					$chain_rule .= " -i $interface ";
				}
				foreach my $network ( @networks ) { 
	                        	$main->write_line( "${chain_rule} -s ${network} -j $chain" );
	                        }
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
	my $main = $self->{alff_main};

	print " * Creating rule to allow access to services configured to be world-wide available...";
	print $main->write_line("iptables -A FORWARD -j allowWorldOpenServices") ? "done.\n" : "FAILED\n";
} #}}}

################################################################################
#			    Service chains handling			       #
################################################################################

##
# Read the names of all configured services and return a sort list of them
sub readServiceNames() { #{{{
	my $self = shift;
	my $services_d = $self->{services_d};
	my @services;

	return undef if ( ! -d $services_d );

	if ( ! opendir( SERVICE_D, $services_d ) ) {
		print STDERR "Error: Cannot read content of $services_d\n";
		return undef;
	}

	@services = grep { ! m/^\./ and -f "$services_d/$_" } readdir( SERVICE_D );		# read only files and weed out ".*"
	closedir( SERVICE_D );

	return sort @services;
} #}}}

##
# Read the configuration file for this service and return it.
sub readServiceConfiguration($) { #{{{
	my $self = shift;
	my $service = shift;

	my $services_d = $self->{services_d};
	my $service_file = "$services_d/$service";

	return undef if ( ! -d $services_d );
	return undef if ( ! -f $service_file );

	# Read $service_config from config file
	my %service_config;
	require ($service_file);

	return $Alff::Service::Config::service_config;
} #}}}

##
# Generate the service chain for service $_
sub generateServiceChain($) { #{{{
	my $self = shift;
	my $service = shift;

	my $alff = $self->{alff_main};

	my $serviceconfig = $self->readServiceConfiguration( $service );
	my $srv_chain = "allowSrv${service}";

	# Check for config hash
	unless ( $serviceconfig ) {
		print STDERR "Error: Could not read configuration for service $service, skipping...\n";
		return 0;
	}

	# Check it 'servers' is specifed
	unless ( defined $serviceconfig->{servers} ) {
		print STDERR "Error: You need to define at least one server for service $service, skipping...\n";
		return 0;
	}

	# Check if 'ports' is specifed
	unless ( defined $serviceconfig->{ports} ) {
		print STDERR "Error: You need to define at least one server for service $service, skipping...\n";
		return 0;
	}

	# Create a chain for this service
	$alff->write_line( "" );
	$alff->create_chain( $srv_chain, "filter" );

	my @servers = split( /\s+/, $serviceconfig->{servers} );
	my @ports = split(/\s+/, $serviceconfig->{ports} );
	my @valid_ports = ();
	foreach my $port ( @ports ) {
		if ( $self->{alff_validator}->validate_port( $port ) ) {
			push @valid_ports, $port;
		} else {
			print STDERR "ERROR: Invalid port specification $port for service $service, skipping...\n";
		}
	}

	if ( $self->{debug} ) {
		print STDERR "INFO: Service $service, found servers " . join( ', ', @servers ) . " and ports " . join(', ', @valid_ports) . "...\n";
	}

	# Fill the service chain with a server/port matrix
	foreach my $server ( @servers ) {
		# Beware of to much spaces in config file...
		chomp $server;
		next if ( $server eq "" );

		foreach my $service_port ( @valid_ports ) {
			# Beware of to much spaces in config file...
			chomp $service_port;
			next if ( $service_port eq "" );

			if ( $service_port =~ m/([[:digit:]:]+)\/(tcp|udp)/ ) {
				my ( $port, $proto ) = ( $1, $2 );
				$alff->write_line( "iptables -A $srv_chain -p $proto -d $server --dport $port -j ACCEPT" );
			}
		}
	}

	# Allow service for configured security classes
	foreach my $config_key ( keys %{$serviceconfig} ) {
		# search for security classes
		if ( $config_key =~ m/allow_from_(\w+)_networks/ && $serviceconfig->{$config_key} eq "yes" ) {
			my $sec_class = $1;
			my $sec_class_chain = "allowServicesFrom" . ucfirst( $sec_class ) . "Nets";

			if ( $alff->chain_exists( $sec_class_chain ) ) {
				$alff->write_line( "iptables -A $sec_class_chain -j $srv_chain" );
			} else {
				print STDERR "Error: Service $service should be accessable from undefined security class $sec_class, skipping...\n";
			}
		}
	}

	# public accessable service?
	if ( defined $serviceconfig->{allow_from_world} and $serviceconfig->{allow_from_world} eq "yes" ) {
		$alff->write_line( "iptables -A allowWorldOpenServices -j $srv_chain" );
	}
} #}}}

1;
# vim:foldmethod=marker
