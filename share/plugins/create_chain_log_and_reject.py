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

	def run (self, ruleset, site):
		# create fallback chain
		ruleset.create_chain("4", "log_and_reject", "filter")
		ruleset.create_chain("6", "log_and_reject", "filter")

		# LOG the traffic to be rejected, but restrict the amount of logs...
		ruleset.add_rule('iptables -A log_and_reject -m limit --limit 3/sec --limit-burst 5 -j LOG --log-prefix "alff rejected: "')
		ruleset.add_rule('ip6tables -A log_and_reject -m limit --limit 3/sec --limit-burst 5 -j LOG --log-prefix "alff rejected: "')
		
		# REJECT tcp connections gently by sending a tcp-reset
		ruleset.add_rule('iptables -A log_and_reject -p tcp -j REJECT --reject-with tcp-reset')
		ruleset.add_rule('ip6tables -A log_and_reject -p tcp -j REJECT --reject-with tcp-reset')
	
		# REJECT anything else via an ICMP message with icmp-admin-prohibited
		ruleset.add_rule('iptables -A log_and_reject -j REJECT --reject-with icmp-admin-prohibited')
		ruleset.add_rule('ip6tables -A log_and_reject -j REJECT --reject-with icmp6-adm-prohibited')
