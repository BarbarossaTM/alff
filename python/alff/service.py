#!/usr/bin/python
#
#  A Linux Firewall Framework
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
# Maximilian Wilhelm <max@rfc2324.org>
#  --  Sat 04 Jan 2014 01:38:09 AM CET
#

import os.path

from alff.errors import *
from alff.utils  import *

class Service (object):

	def __init__ (self, config, ruleset, site, log):
		self.config = config
		self.ruleset = ruleset
		self.site = site
		self.log = log

		self.services_d = join_path (self.config.get_config_dir (), "services.d")

		if not os.path.isdir (self.services_d):
			raise ConfigError ("Error: Missing 'services.d' directory in config dir '%s'." % self.config.get_config_dir ())


	def allow_service_from_networks_of_security_class (self, sec_class):
		chain = "allowSrvFrom" + sec_class.capitalize () + "Nets"
		vlans = self.config.get_vlans_of_security_class (sec_class)

		self.log.info ("Allowing access to services configured to be available from networks of sec. class %s..." % sec_class)

		if len (vlans) == 0:
			self.log.warn ("Attention: There are not networks of security class %s, staying cool." % sec_class)
			return

		for vlan in vlans:
			networks = self.config.get_vlan_networks (vlan)
			# XXX Gute Idee, hier immer auch das default-if zu nehmen?
			interface = self.config.get_vlan_interface (vlan, self.site, use_default = True)

			for net in networks:
				cmd = "iptables" if ip_version (net) == 4 else "ip6tables"
				self.ruleset.add_rule (cmd + "-A FORWARD -s %s -i %s -j %s" % (net, interface, chain))


	def allow_world_open_services (self):
		pass

	def read_service_names (self):
		pass

	def read_service_configuration (self):
		pass

	def generate_service_chain (self):
		pass

