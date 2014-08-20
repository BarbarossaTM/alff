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

		self.allow_icmp = self.config.get_option ("allow_icmp") 

	def run (self, ruleset, site):
		# create chains
		ruleset.create_chain("4", "handleICMP", "filter")
		ruleset.create_chain("6", "handleICMP", "filter")
		ruleset.add_rule("iptables -A FORWARD -p icmp -j handleICMP")
		ruleset.add_rule("ip6tables -A FORWARD -p icmpv6 -j handleICMP")

		# list of basic icmp4-types
		# echo-reply, destination-unreachable, source-squench, echo-request
		# time-exceeded, parameter-problem
		allowed_icmp4 = [0, 3, 4, 8, 11, 12]

		# list of basic icmp6-types
		# Destination Unreachable, Packet too big, time exceeded, parameter problem
		# echo request, echo reply
		# See section 4.3 in RFC 4890
		allowed_icmp6 = [1, 2, 3, 4, 128, 129]

		if self.allow_icmp == "all":
			# We have no fear, allow all icmp traffic
			ruleset.add_rule("iptables -A handleICMP -p icmp -j ACCEPT")
			ruleset.add_rule("ip6tables -A handleICMP -p icmpv6 -j ACCEPT")
		elif self.allow_icmp == "basic":
			# allow icmptypes defined as basic icmp types
			for icmp_type in allowed_icmp4:
				ruleset.add_rule("iptables -A handleICMP -p icmp -m icmp --icmp-type %s -j ACCEPT" % icmp_type)
			for icmp_type in allowed_icmp6:
				ruleset.add_rule("ip6tables -A handleICMP -p icmpv6 --icmpv6-type %s -j ACCEPT" % icmp_type)
			ruleset.add_rule("iptables -A handleICMP -p icmp -j REJECT --reject-with icmp-admin-prhobited")
			ruleset.add_rule("ip6tables -A handleICMP -p icmpv6 -j REJECT --reject-with icmp6-adm-prohibited")
		else:
			# allow nothing (REALLY BAD IDEA!)
			ruleset.add_rule("iptables -A handleICMP -p icmp -j REJECT --reject-with icmp-admin-prhobited")
			ruleset.add_rule("ip6tables -A handleICMP -p icmpv6 -j REJECT --reject-with icmp6-adm-prohibited")

