#!/usr/bin/python
#
#  Linux Firewall Framework
#
#  Copyright (C) 2014 Maximilian Wilhelm <max@rfc2324.org>
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
#  Michael Schwarz <schwarz@upb.de> 
#  --  Mon 14 Apr 2014 07:55:55 PM CEST
#

import os
import re

from alff.errors import *
from alff.plugin import BasePlugin
from alff.utils  import *
from alff.service import *

class Plugin (BasePlugin):
	def __init__ (self, config, log):
		BasePlugin.__init__ (self, config, log)
		self.config = config
		self.log = log

		self.services_d = join_path (self.config.get_config_dir (), "services.d")

		if not os.path.isdir (self.services_d):
			raise ConfigError ("Error: Missing 'services.d' directory in config dir '%s'." % self.config.get_config_dir ())

	def run (self, ruleset, site):
		# find all files in service.d-dir
		configured_services = [ f for f in os.listdir(self.services_d) if os.path.isfile(self.services_d+'/'+f) ]

		# create and set up service chains
		for service_name in configured_services:
			self.log.debug("Processing service %s ..." % service_name)
			service = Service(self.config, self.log, service_name)
			
			srv_chain = service.get_chain_name()
			
			ruleset.create_chain(4, srv_chain)
			ruleset.create_chain(6, srv_chain)

			for host in service.get_hosts():
				for port in service.get_ports():

					m = re.search('(\d+)/(tcp|udp)', port)
					port_number = m.group(1)
					port_proto = m.group(2)

					cmd = "iptables" if ip_version(host) == 4 else "ip6tables"
					rule = ("%s -A %s -p %s -d %s --dport %s -j ACCEPT" % (cmd, srv_chain, port_proto, host, port_number))
					ruleset.add_rule(rule)


			# tie servicechain into ruleset
			# allow from special networks
			for network in service.get_allowed_networks():
				sec_class_chain = "allowSrvFrom%sNets" % network
	
				if not ruleset.chain_exists(4, sec_class_chain):
					ruleset.create_chain(4, sec_class_chain)
					ruleset.add_rule("iptables -A FORWARD -j %s" % sec_class_chain)
				if not ruleset.chain_exists(6, sec_class_chain):
					ruleset.create_chain(6, sec_class_chain)
					ruleset.add_rule("ip6tables -A FORWARD -j %s" % sec_class_chain)
	
				ruleset.add_rule("iptables -A %s -j %s" % (sec_class_chain, srv_chain))
				ruleset.add_rule("ip6tables -A %s -j %s" % (sec_class_chain, srv_chain))
	
			# is service supposed to be public accessible
			if not ruleset.chain_exists(4, 'allowWorldOpenServices'):
				ruleset.create_chain(4, 'allowWorldOpenServices')
				ruleset.add_rule("iptables -A FORWARD -j allowWorldOpenServices")
			if not ruleset.chain_exists(6, 'allowWorldOpenServices'):
				ruleset.create_chain(6, 'allowWorldOpenServices')
				ruleset.add_rule("ip6tables -A FORWARD -j allowWorldOpenServices")
	
			if service.allow_from_world():
				ruleset.add_rule("iptables -A allowWorldOpenServices -j %s" % srv_chain)
				ruleset.add_rule("ip6tables -A allowWorldOpenServices -j %s" % srv_chain)
