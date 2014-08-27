#!/usr/bin/perl 
#
# Convert old Service-Configs to json-files
#
# Michael Schwarz <schwarz@upb.de>
# -- Tue 27 Aug 2014 07:55:55 PM CEST

if ($#ARGV + 1 < 2) {
	print "FEHLER: Keine Source und Destination-Datei übergeben\n";
	print "FEHLER: Programm wie folgt aufrufen:\n";
	print "FEHLER: convertService.pl OLDFILE NEWFILE\n";
	exit(1);
}

$src_file = $ARGV[0];
$dst_file = $ARGV[1];

print "Konvertiere $src_file ins JSON-Format.\n";

if (-e $dst_file) {
	print "FEHLER: Zieldatei existiert schon, breche ab\n";
	exit(3);
}

if (-e $src_file) {
	require($src_file);
	$serviceConfig = $Alff::Service::Config::service_config;

	my @servers = split( /\s+/, $serviceConfig->{servers} );
	my @ports = split(/\s+/, $serviceConfig->{ports} );

	open(DSTFILE, ">>$dst_file");

	print DSTFILE "{\n";
	print DSTFILE "\t\"servers\" : [\n";

	foreach my $server (@servers) {
		print DSTFILE "\t\t\"$server\",\n";
	}

	print DSTFILE "\t],\n";
	print DSTFILE "\t\"ports\" : [\n";

	foreach my $port (@ports) {
		print DSTFILE "\t\t\"$port\",\n";
	}
	print DSTFILE "\t]";

	foreach my $config_key ( keys %{$serviceConfig} ) {
		if ($config_key =~ m/allow_from_.+/) {
			print DSTFILE ",\n\t\"$config_key\": \"$serviceConfig->{$config_key}\"";
		}
	}

	print DSTFILE "\n}";

	close DSTFILE;

} else {
	print "FEHLER: Quelldatei existiert nicht\n";
	exit(2);
}
