#!/usr/bin/python3
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
#  --  Sat 12 Apr 2014 08:46:44 PM CEST
#

import subprocess
from alff.errors	import *
from alff.function	import *
import time
import hashlib


# argparse configuration
args_config = {
	"_help" : "Push rules to firewalls",
	"site" : {
		"_order" : 1,
		"nargs" : "*",
		"help" : "Site to push rules to",
		"default" : "ALL",
	},

	"fw" : {
		"_order" : 2,
		"nargs" : "*",
		"help" : "Firewall at _site_ to push rules to",
		"default" : "ALL",
	},
}


class Function (BaseFunction):
	def __init__ (self,config,args,log):
		BaseFunction.__init__ (self, config, args, log)

	def validate_config (self):
		if 'ALL' in self.args.site:
			self.sites = self.config.get_sites ()
			return

		for site in self.args.site:
			if not self.config.is_valid_site (site):
				raise ConfigError ("Site '%s' not found in configuration." % site)

		self.sites = self.args.site

	def run (self):

		execute_hooks ("prepush", "ALL", self.config, self.log)

		# TODO Regeln an einzelne Maschinen uebertragen
		for site in self.sites:
			# execute hooks
			execute_hooks ("prepush", site, self.config, self.log)

			self.log.info("Pushing Rules to (specified) Firewalls at site '%s'" % site)
			machines = self.config.get_machine_ids(site)
			for machine in machines:
				# We will push and load the ruleset in two steps.
				# This will prevent loading rules only on some of the firewalls.
				self._push_ruleset(site, machine)

		for site in self.sites:
			self.log.info("Loading rulesets at site '%s'" % site)
			machines = self.config.get_machine_ids(site)
			for machine in machines:
				# finally load the previously pushed rules
				self._init_and_validate_loading(site, machine)

			#execute hooks
			execute_hooks ("postpush", site, self.config, self.log)

		execute_hooks ("postpush", "ALL", self.config, self.log)

	def _push_ruleset(self, site, machine):
		self.log.info("\tPushing ruleset to '%s'" % machine)

		# prefer ipv6-address of firewall
		if self.config.get_machine_hostname(machine, site):
			host = self.config.get_machine_hostname(machine, site)
		elif self.config.get_machine_ip6(machine, site):
			host = self.config.get_machine_ip6(machine, site)
		else:
			host = self.config.get_machine_ip(machine, site)

		if host == None:
			raise RuntimeError ("Invalid ip specification for machine '%s', specify either hostname, ipv4 or ipv6 address." % machine)

		filename_v4 = "%s/%s/%s_4.rules" % (self.config.get_rules_base_dir(), site, site)
		filename_v6 = "%s/%s/%s_6.rules" % (self.config.get_rules_base_dir(), site, site)

		command = ["/usr/bin/scp", "-Bq", filename_v4, "root@%s:/var/cache/alff/rules/rules.current" % host]
		scp = subprocess.call (command)
		if scp != 0:
			raise AlffError ("Copy of IPv4 ruleset to '%s' failed ..." % machine)

		command = ["/usr/bin/scp", "-Bq", filename_v6, "root@%s:/var/cache/alff/rules/rules_v6.current" % host]
		scp = subprocess.call (command)
		if scp != 0:
			raise AlffError ("Copy of IPv6 ruleset to '%s' failed ..." % machine)


	def _init_and_validate_loading(self, site, machine):
		# calculate md5sum of rulesets
		filename_v4 = "%s/%s/%s_4.rules" % (self.config.get_rules_base_dir(), site, site)
		filename_v6 = "%s/%s/%s_6.rules" % (self.config.get_rules_base_dir(), site, site)

		md5sum_v4 = hashlib.md5(open(filename_v4, 'rb').read()).hexdigest()
		md5sum_v6 = hashlib.md5(open(filename_v6, 'rb').read()).hexdigest()

		self.log.info("\tLoading ruleset on '%s'" % machine)

		# prefer ipv6-address of firewall
		if self.config.get_machine_hostname(machine, site):
			host = self.config.get_machine_hostname(machine, site)
		elif self.config.get_machine_ip6(machine, site):
			host = self.config.get_machine_ip6(machine, site)
		else:
			host = self.config.get_machine_ip(machine, site)

		if host == None:
			raise RuntimeError ("Invalid ip specification for machine '%s', specify either hostname, ipv4 or ipv6 address." % machine)


		command = ["/usr/bin/ssh", "-q", "root@%s" % host, "/usr/sbin/alff-cat %s %s" % (md5sum_v4, md5sum_v6) ]
		ssh = subprocess.call (command)
		if ssh != 0:
			raise AlffError ("Failed to load rules on '%s' ..." % machine)
		pass

		time.sleep(1)

		self.log.info("\t\tValidating")
		command = ["/usr/bin/ssh", "-q", "root@%s" % host, "source /etc/alff/alff-defaults.conf ; if [ -f ${DELETE_ME_TOKEN} ] ; then rm -f ${DELETE_ME_TOKEN} ; fi" ]
		ssh = subprocess.call (command)
		if ssh != 0:
			raise AlffError ("Sorry i couldn't delete the security token. Ruleset will be reverted in some seconds")
		pass

