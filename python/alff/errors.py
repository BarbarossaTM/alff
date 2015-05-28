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
#  --  Sat 04 Jan 2014 01:33:51 AM CET
#

import warnings


class AlffError (Exception):
	def __init__ (self, message):
		self.message = message

	def __str__ (self):
		return "%s" % (self.message)


class RulesetError (AlffError):
	def __init__ (self, message, rule = None):
		self.message = message
		self.rule = rule

	def __str__ (self):
		if self.rule:
			return "Invalid rule '%s': %s" % (self.rule.strip (), self.message)

		return str (self.message)


class ConfigError (AlffError): pass
class PluginError (AlffError): pass
class UnhandledError (AlffError): pass
class NotImplementedError (AlffError): pass


def AlffDeprecated (old, new):
	warnings.warn ("%s is deprecated, use %s instead." % (old, new), Warning, stacklevel = 3)
