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
#  --  Sat 04 Jan 2014 10:29:29 PM CET
#

import inspect
import os
import os.path

from   alff.errors import *
from   alff.utils  import *
import subprocess

FUNCTION_DIRS = ( "/usr/lib/python2.7/dist-packages/alff/alff/function", "/etc/alff/functions" )

class BaseFunction (object):

	def __init__ (self, config, args, logger_instance):
		self.config = config
		self.args = args
		self.log = logger_instance


	def validate_config (self):
		raise NotImplementedError ("Some lazy bastard didn't implement the 'validate_config' method for this function. Please go and haunt him..")


	def run (self):
		raise NotImplementedError ("Some lazy bastard didn't implement the 'run' method for this function, so I've no idea what to do now..")



def load_functions (log):
	functions = {}

	# Gather up list of functions dirs containing
	#  * the directory paths specified as colon spearated list in ALFF_FUNCTION_DIRS env var, if present
	#  * the default function dirs as specified in FUNCTION_DIRS, containg the distributen functions and
	#    any user created functions in Alffs main configuration directory.
	function_dirs = []

	if 'ALFF_FUNCTION_DIRS' in os.environ:
		log.info ("Loading functions from ALFF_FUNCTION_DIRS dirs!")
		function_dirs.extend (os.environ["ALFF_FUNCTION_DIRS"].split (":"))

	function_dirs.extend (FUNCTION_DIRS)

	for dir in function_dirs:
		if not os.path.isdir (dir):
			continue

		modules = [m for m in os.listdir (dir) if m.endswith (".py") and m != "__init__.py" ]

		for file_name in modules:
			func_name = file_name.replace (".py", "")
			file_path = "%s/%s" % (dir, file_name)

			if func_name in functions:
				log.debug ("Ignoring function '%s' from '%s' in favour of one from '%s'." %
				(func_name, dir, functions[func_name].__file__.replace ("/%s.pyc" % func_name, "")))

				continue

			try:
				functions[func_name] = load_module_from_file ("alff.function.%s" % func_name, file_path)
			except AlffError as a:
				raise AlffError ("Error while loading function: %s" % a)

	return functions


def execute_hooks (hookname, site, config, log):
	print("Executing hooks: %s, Site: %s" % (hookname, site))
	hook_dir = "%s/hooks.d/%s/%s" % (config.get_config_dir (), hookname, site)

	# If there is no configuration dirctory for this hook,
	# there's nothing to do here.
	if not os.path.isdir (hook_dir):
		return

	# only call executeable files
	# hooks must return either return value 0 if everything went fine or
	# value > 0 if not. Generation of ruleset will end on any error
	hooks = [f for f in os.listdir(hook_dir) if os.path.isfile(hook_dir + "/" + f) and os.access(hook_dir + "/" + f, os.X_OK) ]
	count = len(hooks)
	i = 0
	for hook in hooks:
		i += 1
		print("[%s/%s] %s" % (i, count, hook))
		hook_path = hook_dir + "/" + hook

		# execute hooks
		try:
			# set some ALFF-specific environment variables and concat environment from the calling shell
			envvars = {'ALFF_SITE': site, 'ALFF_CONFIG_DIR': config.get_config_dir()}
			for key, var in os.environ.iteritems():
				envvars[key] = var

			proc = subprocess.Popen(hook_path, shell=True, env=envvars, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			output = proc.communicate()
			retcode = proc.returncode

			if retcode > 0:
				raise AlffError ("Error while executing hook %s: %s" % (hook, output[1]))

			# provide output
			if output[0]:
				stdout = output[0]
				for line in iter(stdout.splitlines(True)):
					line = line.replace("\n", "")
					print ("[%s/%s] %s: %s" % (i, count, hook, line))

		except OSError as e:
			raise AlffError ("Error while executing hook %s: %s" % hook, e)
