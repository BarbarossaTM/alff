#!/usr/bin/python
#
#  A Linux Firewall Framework
#
#  Copyright (C) 2015 Maximilian Wilhelm <max@rfc2324.org>
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
# alff configuration checking function
#
# Maximilian Wilhelm <max@rfc2324.org>
#  --  Thu 28 May 2015 08:38:58 PM CEST
#

import os.path

from	alff.errors	import *
from	alff.function	import *

# argparse configuration
args_config = {
	"_help" : "Validate configuration",
}


class Function (BaseFunction):

	def __init__ (self, config, args, log):
		BaseFunction.__init__ (self, config, args, log)

		# Configuration directory containg all plugins used for ruleset generation
		self.plugin_dir = "%s/plugin.d" % self.config.get_config_dir ()
		if not os.path.isdir (self.plugin_dir):
			raise ConfigError ("Error: Plugin configuration dir '%s' does not exist!" % self.plugin_dir)


	def validate_config (self):
		# Pass for now an rely on alff config parser to do it's work
		pass

	def run (self):
		# Pass for now an rely on alff config parser to do it's work
		pass
