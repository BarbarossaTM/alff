#!/usr/bin/python3
#
#  Linux Firewall Framework
#
#  Copyright (C) 2014 Maximilian Wilhelm <max@rfc2324.org>,
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License along
#  with this program; if not, write to the Free Software Foundation, Inc.,
#  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Maximilian Wilhelm <max@rfc2324.org>
#  --  Mon 14 Apr 2014 07:55:55 PM CEST
#

from alff.errors import *
from alff.plugin import BasePlugin
from alff.utils  import *

import re, os

class Plugin (BasePlugin):
	def __init__ (self, config, log):
		BasePlugin.__init__ (self, config, log)

		self.dhcp_servers = self.config.get_option("dhcp_server")

	def run (self, ruleset, site):
		filename = os.path.basename(__file__)
		match = re.search('\d*enable_DHCP_relay_(?P<chain>[a-zA-Z_]+)\.py', filename)
		chain = match.group('chain')

		if chain != "INPUT" and chain != "FORWARD":
			raise RulesetError("Link must end on INPUT.py or FORWARD.py")

		# Is this plugin linked as Input?
		if chain == "INPUT":
			ruleset.add_rule("iptables -A INPUT -p udp -d 255.255.255.255 --sport 68 --dport 67 -j ACCEPT")
			ruleset.add_rule("ip6tables -A INPUT -p udp -d ff02::1:2 --sport 546 --dport 547 -j ACCEPT")
			for server in self.dhcp_servers:
				if ip_version (server) == 4:
					ruleset.add_rule("iptables  -A INPUT -p udp -s %s --sport 67 -j ACCEPT" % server)
				elif ip_version (server) == 6:
					ruleset.add_rule("ip6tables  -A INPUT -p udp -s %s --sport 547 -j ACCEPT" % server)
				else:
					raise ConfigError("Malformed DHCP-Address: %s" % server)

		# Is this plugin linked as Forward?
		if chain == "FORWARD":
			ruleset.create_chain("4", "allowDHCP", "filter")
			ruleset.create_chain("6", "allowDHCP", "filter")

			ruleset.add_rule("iptables -A FORWARD -p udp --sport 67:68 --dport 67:68 -j allowDHCP")
			ruleset.add_rule("ip6tables -A FORWARD -p udp --sport 546:547 --dport 546:547 -j allowDHCP")

			for server in self.dhcp_servers:
				if ip_version (server) == 4:
					ruleset.add_rule("iptables -A allowDHCP -d %s -p udp --sport 68 --dport 67 -j ACCEPT" % server)
					ruleset.add_rule("iptables -A allowDHCP -s %s -p udp --sport 67 --dport 68 -j ACCEPT" % server)
					ruleset.add_rule("iptables -A allowDHCP -s %s -p udp --sport 67 --dport 67 -j ACCEPT" % server)
					for relay_site in self.config.get_sites():
						for machine in self.config.get_machine_ids(relay_site):
							relay = self.config.get_machine_ip(machine, relay_site)
							if relay and ip_version (relay) == 4:
								ruleset.add_rule("iptables -A allowDHCP -s %s -d %s -p udp --sport 67 --dport 67 -j ACCEPT" % (relay, server))
				elif ip_version (server) == 6:
					ruleset.add_rule("ip6tables -A allowDHCP -d %s -p udp --sport 546 --dport 547 -j ACCEPT" % server)
					ruleset.add_rule("ip6tables -A allowDHCP -s %s -p udp --sport 547 --dport 546 -j ACCEPT" % server)
					ruleset.add_rule("ip6tables -A allowDHCP -s %s -p udp --sport 547 --dport 547 -j ACCEPT" % server)
					for relay_site in self.config.get_sites():
						for machine in self.config.get_machine_ids(relay_site):
							relay = self.config.get_machine_ip6(machine, relay_site)
							if relay and ip_version (relay) == 6:
								ruleset.add_rule("ip6tables -A allowDHCP -s %s -d %s -p udp --sport 67 --dport 67 -j ACCEPT" % (relay, server))
				else:
					raise ConfigError("Malformed DHCP-Address: %s" % server)
