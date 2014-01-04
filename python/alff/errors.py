#!/usr/bin/python
#
# Maximilian Wilhelm <max@rfc2324.org>
#  --  Sat 04 Jan 2014 01:33:51 AM CET
#

class AlffError (Exception):
	def __init__ (self, message):
		self.message = message

	def __str__ (self):
		return "%s" % (self.message)

class ConfigError (AlffError): pass
class PluginError (AlffError): pass
class RulesetError (AlffError): pass
class UnhandledError (AlffError): pass
class NotImplementedError (AlffError): pass
