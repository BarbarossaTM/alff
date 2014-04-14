#!/usr/bin/python
#
# Maximilian Wilhelm <max@rfc2324.org>
#  --  Sat 04 Jan 2014 10:29:29 PM CET
#

import inspect
import os
import os.path

from   alff.errors import *
from   alff.utils  import *

FUNCTION_DIRS = ( "/usr/share/alff/function", "/etc/alff/functions" )

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


def execute_hooks (hookname, config, log):
	hook_dir = "%s/hook.d/%s" % (config.get_config_dir (), hookname)

	# If there is no configuration dirctory for this hook,
	# there's nothing to do here.
	if not os.path.isdir (hook_dir):
		return

	# TODO  actual magic  TODO
