
#!/usr/bin/python
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

plugin_name = "createChainTcpScanHandling"

class Plugin (BasePlugin):
	def __init__ (self, config, log):
		BasePlugin.__init__ (self, config, log)

		# set options
		self.loglevel = "info"
		self.log_scans = self.config.get_plugin_option (plugin_name, "log_scans", True)
		self.drop_scans = self.config.get_plugin_option (plugin_name, "drop_scans", True)
		self.hook_in_input = self.config.get_plugin_option (plugin_name, "hook_in_input", True) 
		self.hook_in_forward = self.config.get_plugin_option (plugin_name, "hook_in_forward", True) 

	def run (self, ruleset, site):
		# create chains
		ruleset.create_chain("4", "tcp_scan_handling", "filter")
		ruleset.create_chain("6", "tcp_scan_handling", "filter")

		# define scan symptoms
		scans = {'ALL': {'FIN,URG,PSH': 'Stealth XMAS scan',
						'SYN,RST,ACK,FIN,URG': 'Stealth XMAS-PSH scan',
						'ALL': 'Stealth XMAS-ALL scan',
						'FIN': 'Stealth FIN scan',
						'NONE': 'Stealth Null scan'},
				'SYN,RST': {'SYN,RST': 'Stealth SYN/RST scan'},
				'SYN,FIN': {'SYN,FIN': 'Stealth SYN/FIN scan(?)'}}

		#build rules
		if self.log_scans:
			for flagSearch in scans:
				for flagSet in scans[flagSearch]:
					name = scans[flagSearch][flagSet]

					rule = "-A tcp_scan_handling -p tcp --tcp-flags %s %s " % (flagSearch, flagSet)
					rule += "-m limit --limit 3/m --limit-burst 5 -j LOG --log-level %s " % self.loglevel
					rule += '--log-prefix "%s"' % name

					rulev4 = "iptables " + rule
					rulev6 = "ip6tables " + rule
					ruleset.add_rule(rulev4)
					ruleset.add_rule(rulev6)
		
		if self.drop_scans:
			for flagSearch in scans:
				for flagSet in scans[flagSearch]:

					rule = "-A tcp_scan_handling -p tcp --tcp-flags %s %s " % (flagSearch, flagSet)
					rule += "-m limit --limit 3/m --limit-burst 5 -j DROP"

					rulev4 = "iptables " + rule
					rulev6 = "ip6tables " + rule
					ruleset.add_rule(rulev4)
					ruleset.add_rule(rulev6)

		if self.hook_in_input:
			ruleset.add_rule("iptables -A INPUT -j tcp_scan_handling")
			ruleset.add_rule("ip6tables -A INPUT -j tcp_scan_handling")

		if self.hook_in_forward:
			ruleset.add_rule("iptables -A FORWARD -j tcp_scan_handling")
			ruleset.add_rule("ip6tables -A FORWARD -j tcp_scan_handling")
