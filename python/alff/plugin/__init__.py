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
#  --  Sat 04 Jan 2014 10:34:07 PM CET
#

from alff.errors import *

class BasePlugin (object):

	def __init__ (self, config, log):
		object.__init__ (self)

		# Simply store these things as attributes for now
		self.config = config
		self.log = log


	def run (self, ruleset, site):
		"""
		This method will be called when the plugin is due to be executed.
		"""

		raise NotImplmentedError ("Some lazy bastard didn't forgot to implement this function..")
