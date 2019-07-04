#!/usr/bin/python3
#
#  Linux Firewall Framework
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
#  --  Sat 04 Jan 2014 01:37:53 AM CET
#

from importlib.machinery import SourceFileLoader
import inspect
import ipaddress
import os

from alff.errors import *


def load_module_from_file (module_name, path):
	try:
		module = SourceFileLoader(module_name, path).load_module()
	except ImportError as i:
		raise AlffError ("Failed to load module from '%s': %s" % (path, i))
	except Exception as e:
		raise AlffError ("Unknown error while loading module from '%s': %s" % (path, e))

	return module


def get_class (module, class_name):
	# Figure out module name
	try:
		module_file = module.__file__.replace ('.pyc', '.py')
	except AttributeError as a:
		raise AlffError ("Module seems to be broken or invalid.")

	# Get class
	try:
		# The attribue named <class_name> from module
		module_class = getattr (module, class_name)

		# Is it a class?
		if not inspect.isclass (module_class):
			raise AlffError ("Attribute '%s' found in module '%s' (%s) is not a class." % (class_name, module.__name__, module_file))
	except AttributeError as e:
		raise AlffError ("No class '%s' found in module '%s' (%s)." % (class_name, module.__name__, module_file))

	return module_class


def join_path (*components):
	return os.path.normpath (os.sep.join (components))


def ip_version (ip):
	obj = ipaddress.ip_interface(ip)

	return obj.version
