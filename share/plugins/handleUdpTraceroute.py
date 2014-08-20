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

class Plugin (BasePlugin):
	def __init__ (self, config, log):
		BasePlugin.__init__ (self, config, log)

		self.allow_traceroute_udp = self.config.get_option ("allow_traceroute_udp") 

	def run (self, ruleset, site):
		if self.allow_traceroute_udp == "yes":
			ruleset.add_rule("iptables -A FORWARD -p udp --dport 33434:33523 -j ACCEPT")
			ruleset.add_rule("ip6tables -A FORWARD -p udp --dport 33434:33523 -j ACCEPT")

