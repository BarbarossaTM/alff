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
#  --  Sat 04 Jan 2014 04:33:57 AM CET
#

import argparse
import json
import logging
import sys


import	alff.config
import	alff.function
from	alff.errors	import *
from	alff.utils	import *

# Default settings
DEFAULT_CONFIG_DIR = "/etc/alff/default"

#
# Setup logging
try:
	log = logging.getLogger ("alff")
	log.setLevel (logging.INFO)

	sh = logging.StreamHandler ()
	sh.setFormatter (logging.Formatter ("%(message)s"))
	log.addHandler (sh)

	# Manually check if we should be verbose about what's going on as
	# waiting for argparse to may be too late for some components (like
	# loading of functions).
	if "-v" in sys.argv or "--verbose" in sys.argv:
		log.setLevel (logging.DEBUG)
except Exception as e:
	print ("Failed to set up logging: %s".format(e), file=sys.stderr)

log.info ("The ALFF Linux Firewall Framework awakes...")


################################################################################
#
# Command line argument parsing

# Gather command parameters from cmd_dict for argparse usage
def _get_params (cmd_dict):
	class Params () : pass

	params = {}

	params['nargs'] = None
	params['default'] = None

	for param in cmd_dict.keys ():
		# Skip metainfo "params"
		if param[0] != '_':
			params[param] = cmd_dict[param]

	if 'action' in params:
		del params['nargs']

	return params


# Load all available function modules and configure argparse accordingly
try:
	function_modules = alff.function.load_functions (log)
	if len (function_modules) == 0:
		raise AlffError ("No functions found on your system. Please check your installation.")
except AlffError as a:
	log.error (a)
	sys.exit (1)
except Exception as e:
	log.critical ("An unhandled error occured while loading functions: %s" % e)
	sys.exit (2)

parser = argparse.ArgumentParser (prog = "alff")
parser.add_argument ("--config-dir", "-c", help = "config directory", default = DEFAULT_CONFIG_DIR)
parser.add_argument ("--verbose", "-v",    help = "Be verbose", action = "store_true", default = False)
subparsers = parser.add_subparsers (title = 'functions', dest = "func")

for func in function_modules.keys ():
	func_module = function_modules[func]
	args_config = getattr (func_module, "args_config", {})

	func_p = subparsers.add_parser (func, help = args_config.get ("help", ""))

	for arg in args_config.keys ():
		if arg[0] == "_":
			continue

		params = _get_params (args_config[arg])
		func_p.add_argument (arg, **params)

args = parser.parse_args ()


#
# Load configuration
try:
	log.debug ("Loading configuration from '%s'..." % args.config_dir)
	config = alff.config.Config (args.config_dir)
except AlffError as a:
	log.error ("Failed to load configuration: %s" % a)
	sys.exit (1)
except Exception as e:
	log.critical ("An unhandled error occurred while loading main configuration: %s" % e)
	sys.exit (2)


#
# Let the show begin
try:
	# Load function called for on cmdline using the previously loaded module
	# to avoid any surprise by changed module file or anything the like.
	module = function_modules[args.func]

	try:
		log.debug ("Initializing function '%s'.." % args.func)

		constructor = get_class (module, "Function")

		func = constructor (config, args, log)
	except AlffError as a:
		raise AlffError ("Error while loading function %s: %s" % (func_name, a))
	except Exception as e:
		raise AlffError ("Unhandler error while loading functon %s: %s" % (args.func, e))

	try:
		log.debug ("Validating configuration and paramters..")
		func.validate_config ()
	except ConfigError as c:
		raise AlffError ("Sorry, I can't run '%s': %s" % (args.func, c))

	try:
		log.debug ("Executing function %s.." % args.func)
		func.run ()
	except AlffError as a:
		raise AlffError ("Error while running '%s': %s" % (args.func, a))

except PluginError:
	pass

except AlffError as a:
	log.error (a)
	sys.exit (1)
except Exception as e:
	log.critical ("An unhandled error occurred: %s" % e)
	sys.exit (2)
