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

import os
import json
import re

from alff.errors import *
from alff.utils  import *

class Service (object):

	def __init__ (self, config, log, service_name):
		self.config = config
		self.log = log
		self.service_name = service_name

		self.services_d = join_path (self.config.get_config_dir (), "services.d")

		if not os.path.isdir (self.services_d):
			raise ConfigError ("Error: Missing 'services.d' directory in config dir '%s'." % self.config.get_config_dir ())

		# Read in service config as json file
		service_file = self.services_d + "/" + service_name
		if os.path.isfile (service_file):
			f = open (service_file, 'r').read()
			self.service_config = json.loads (f)
		else:
			raise ConfigError ("Error: Serviceconfiguration for service name '%s' does not exist." % service_name)

	def get_ports (self):
		temp = []
		for port in self.service_config['ports']:
			if self._validate_port (port):
				temp.append (port)
			else:
				raise ConfigError ("Error: invalid port specification: %s in service %s" % (port, self.service_name))
		return temp

	def get_hosts (self, ipversion = 0):
		if ipversion == 4:
			temp = []
			for ip in self.service_config['servers']:
				if ip_version (ip) == 4:
					temp.append (ip)
			return temp

		elif ipversion == 6:
			temp = []
			for ip in self.service_config['servers']:
				if ip_version (ip) == 6:
					temp.append (ip)
			return temp

		else:
			return self.service_config['servers']

	def get_chain_name (self):
		return "allowSrv" + self.service_name

	def allow_from_world (self):
		if self.service_config.get ('allow_from_world', 'no') == "yes":
			return True

		return False

	def get_allowed_networks (self):
		networks = []
		for key,val in self.service_config.items ():
			m = re.search ('allow_from_(\w+)_networks', key)
			if m:
				if val == "yes":
					networks.append (m.group (1).title ())
		return networks

	# internal methods
	def _validate_port (self, port):
		return True
