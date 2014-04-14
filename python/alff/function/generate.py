#!/usr/bin/python
#
# alff generate function
#
# Maximilian Wilhelm <max@rfc2324.org>
#  --  Thu 10 Apr 2014 11:42:51 PM CEST
#

import logging
import re
import subprocess

from	alff.errors	import *
from	alff.function	import *
import	alff.plugin
from	alff.ruleset	import Ruleset
from	alff.utils		import *

# argparse configuration
args_config = {
	"_help" : "Generate ruleset",
	"site" : {
		"nargs" : "*",
		"help" : "Site to generate rules for",
		"default" : "ALL",
	}
}


class Function (BaseFunction):

	def __init__ (self, config, args, log):
		BaseFunction.__init__ (self, config, args, log)

		# Dict to store ruleset obj for each site
		self.rulesets = {}

		# Configuration directory containg all plugins used for ruleset generation
		self.plugin_dir = "%s/plugin.d" % self.config.get_config_dir ()
		if not os.path.isdir (self.plugin_dir):
			raise ConfigError ("Error: Plugin configuration dir '%s' does not exist!" % self.plugin_dir)

		# List of plugin object to be executed in given order.
		# Will be filled in setup_plugins()
		self.plugins = []


	def validate_config (self):
		if 'ALL' in self.args.site:
			self.sites = self.config.get_sites ()
			return

		for site in self.args.site:
			if not self.config.is_valid_site (site):
				raise ConfigError ("Site '%s' no found in configuration." % site)

		self.sites = self.args.site


	def run (self):
		self._setup_plugins ()

		for site in self.sites:
			self.log.info ("Generating rules for site %s ..." % site)

			# Create ruleset object for this site
			ruleset = Ruleset (self.config, site)
			self.rulesets[site] = ruleset

			# Clear ruleset cache for this site
			ruleset.clear_cache ()

			# Execute any pregenerate hooks, if present
			execute_hooks ("pregenerate", self.config, self.log)

			self._execute_plugins (ruleset, site)

			self._load_user_rules (ruleset)

			# Execute any postgenerate hooks, if present
			execute_hooks ("postgenerate", self.config, self.log)

			ruleset.save_ruleset (4)
			ruleset.save_ruleset (6)

			self.log.info ("Successfully generated and save rulesets for site %s." % site)


	def _setup_plugins (self):
		# Read and plugins in numerical order. Remeber plugins are named 'NNxxxx',
		# where NN is a two digit number indicating execution order.
		try:
			plugins_unsorted = [ f for f in os.listdir (self.plugin_dir) if re.match ("^[0-9]{2}", f) and not f.endswith (".pyc") ]
			plugins = sorted (plugins_unsorted, cmp = lambda x,y: cmp (int (x[0:1]), int (y[0:1])))
		except (IndexError, IOError, ValueError) as e:
			raise ConfigError ("Error reading plugins from configuration dir '%s': %s" % (self.plugin_dir, e))

		if len (plugins) == 0:
			raise ConfigError ("No plugins configured in '%s'. What should I do?!" % self.plugin_dir)

		for plugin in plugins:
			plugin_path = "%s/%s" % (self.plugin_dir, plugin)

			# Each plugin is internally represented as a dict containing:
			#  * the name (as in filename)
			#  * the full path to the plugin file
			#  * An optional python object reference IFF this plugin is a Python module
			#    (as indicated by a .py file suffix). I if isn't a Python module it is
			#    considered an executable which is supposed to output it's rules on
			#    stdout, one on each line.
			plugin_dict = {
				"name" : plugin,
				"file" : plugin_path,
				"pyobj" : None,
			}

			self.plugins.append (plugin_dict)

			# If this looks like a Python plugin, try to load the module and save the
			# instance of the Plugin class in plugin_dict.
			if plugin.endswith (".py"):
				# Remove trailing ".py" from plugin name. If someone _really_ uses
				# "NNpluginX.py" and "NNpluginX" in the plugin.d/ folder both will
				# work finem but show up with the same name and an undefined order.
				plugin = plugin.replace (".py", "")
				plugin_dict["name"] = plugin
				plugin_dict["pyobj"] = self._load_python_plugin (plugin, plugin_path)

			# If this isn't a Python plugin just leave 'pyobj' undefined so we later just
			# execve this thing.



	def _load_python_plugin (self, name, path):
		module_name = "alff.plugin.%s" % name

		self.log.debug ("Loading Python plugin %s" % name)

		try:
			module = load_module_from_file (module_name, path)
		except ImportError as i:
			# XXX FunctionError ?
			raise AlffError ("Failed to load plugin '%s': %s" % (name, i))
		except Exception as e:
			raise AlffError ("Unknowd error while loading plugin '%s': %s" % (name, e))

		try:
			constructor = get_class (module, "Plugin")
			obj = constructor (self.config, logging.getLogger ("alff.plugin"))
		except IndexError:
			raise AlffError ("Failed to instanciate plugin '%s', class 'Plugin' absent?" % name)

		return obj



	def _execute_plugins (self, ruleset, site):
		""" Execute all plugins for the given site with the given ruleset"""

		plugins = self.plugins
		plugins_executed = 0
		num_plugins = len (plugins)
		num_plugin_digits = len (str (num_plugins))

		self.log.info ("Executing plugins...")

		# Run 'em
		for plugin in plugins:
			plugins_executed += 1

			# Print nicely formated status and plugin name
			self.log.info ("[%s/%d] %s" % (str (plugins_executed).zfill (num_plugin_digits), num_plugins, plugin["name"]))

			if plugin["pyobj"]:
				self.__execute_python_plugin (plugin["pyobj"], ruleset, site)

			else:
				# XXX site? XXX
				pass
				self.__execute_regular_plugin (plugin["file"], ruleset)



	def __execute_python_plugin (self, plugin_obj, ruleset, site):
		""" Run Python plugin given as obj reference for the given site producing rules for the given ruleset. """

		try:
			plugin_name = plugin_obj.__module__.split ('.')[-1]
		except AttributeError:
			raise PluginError ("Broken or invalid plugin :-(")

		try:
			plugin_obj.run (ruleset, site)
		except PluginError as p:
			raise AlffError ("An error occured while executing plugin '%s': '%s'" % (plugin_name, p))
		except AlffError as a:
			raise AlffError ("An alff error occured while executing plugin '%s': '%s'" % (plugin_name, a))
		except Exception as e:
			raise AlffError ("An unhandled occured while executing plugin '%s': '%s'" % (plugin_name, e))



	def __execute_regular_plugin (self, path, ruleset):
		# XXX Provide site as parameter to plugins? Useful? XXX
		""" Run regular executable plugin stored at 'path' with the given ruleset. """

		plugin = subprocess.Popen ([path], bufsize = 4194304, stdout = subprocess.PIPE)

		for line in plugin.stdout.readlines ():
			ruleset.add_rule (line)

		plugin.poll ()
		if plugin.returncode == None:
			raise AlffError ("Plugin '%s' didn't terminate after reading rules." % path)



	def _load_user_rules (self, ruleset):
		""" Load non-interVlan rules defined in rules.d/ (not in *_to_* format)"""

		rules_d_path = "%s/rules.d" % self.config.get_config_dir ()

		self.log.info ("Loading user rules..")

		try:
			files = [f for f in os.listdir (rules_d_path) if "_to_" not in f and f != "README" and not f.startswith (".") ]
		except IOError as i:
			raise AlffError ("Failed to read user rule files from rules.d/: %s" % i)

		for file_name in files:
			self.log.debug ("Reading rules file %s.." % file_name)
			file_path = "%s/%s" % (rules_d_path, file_name)
			ruleset.add_rules_from_file (file_path)

