#!/usr/bin/python
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
