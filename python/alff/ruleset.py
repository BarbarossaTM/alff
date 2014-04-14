#!/usr/bin/python
#
# Maximilian Wilhelm <max@rfc2324.org>
#  --  Sat 12 Apr 2014 10:40:43 PM CEST
#

from datetime import datetime
import os
import os.path
import re

from alff.errors import *


DEFAULT_CHAINS = {
	"filter"   : ( "INPUT", "FORWARD", "OUTPUT" ),
	"nat"      : ( "INPUT", "PREROUTING", "POSTROUTING", "OUTPUT" ),
	"mangle"   : ( "PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING" ),
	"raw"      : ( "PREROUTING", "OUTPUT" ),
	"security" : ( "INPUT", "FORWARD", "OUTPUT" ),
}

TABLES = DEFAULT_CHAINS.keys ()


def now ():
	return datetime.now ().strftime ("%a %b %d %H:%M:%S %Y")

class Ruleset (object):

	def __init__ (self, config, site):
		self.config = config
		self.site = site
		self.rules_dir = "%s/%s" % (self.config.get_rules_base_dir (), site)

		if not os.path.isdir (self.rules_dir):
			try:
				os.makedirs (self.rules_dir, 0700)
			except Exception as e:
				raise RulesetError ("Error while creating rules cache dir '%s': %s" % (self.rules_dir, e))

		# Store relevant config option for speedup
		self.suppress_empty_chains = self.config.get_option ("suppress_empty_chains")

		self.ruleset = {
			4 : {},
			6 : {},
		}


		for ruleset in self.ruleset.values ():
			for table in TABLES:
				ruleset[table] = {
					"num_rules" : 0,
					"chains" : {},
				}

				for chain in DEFAULT_CHAINS[table]:
					ruleset[table]["chains"][chain] = {
						"policy" : "ACCEPT",
						"rules" : [],
					}

	def clear_cache (self):
		try:
			for entry in os.listdir (self.rules_dir):
				entry_path = "%s/%s" % (self.rules_dir, entry)
				if not os.path.isfile (entry_path) or os.path.islink (entry_path):
					raise AlffError ("Unexpected non-file entry '%s' found." % entry)

				os.unlink (entry_path)
		except Exception as e:
			raise AlffError ("Error while cleaning cache dir '%s': %s" % (self.rules_dir, e))


	def create_chain (self, protocol, chain, table = "filter"):
		if len (chain) > 30:
			raise RulesetError ("Invalid chain name '%s'. Must be under 30 chars." % chain)

		protocol = _proto_to_int (protocol)

		if protocol not in self.ruleset:
			raise RulesetError ("Invalid protocol '%s'. Try one of %s." % (protocol, ", ".join (self.ruleset.keys ())))

		if table not in TABLES:
			raise RulesetError ("Invalid table '%s'. Try one of %s." % (table, ", ".join (TABLES)))

		if chain not in self.ruleset[protocol][table]["chains"]:
			self.ruleset[protocol][table]["chains"][chain] = {
				"policy" : "-",
				"rules" : [],
			}



	def add_rule (self, string):
		protocol = ""
		table = "filter"
		chain = None
		rule = ""

		mode = None
		insert_at = 0
		policy = None

		# Split command line at white-space boundaries
		cmd = string.split (None)

		# Ignore empty lines
		if len (cmd) == 0 or cmd[0].startswith ('#'):
			return

		if cmd[0] == "iptables":
			protocol = 4
		elif cmd[0] == "ip6tables":
			protocol = 6
		else:
			raise RulesetError ("Rule should start with 'iptables' or 'ip6tables', found '%s'.." % cmd[0], string)

		# Strip first component
		cmd = cmd[1:]

		# Within this block we try to access the next element in the cmd list several times,
		# which may raise an IndexError we don't want to catch at every occurance. So just catch
		# it here once and for all (expect the two places we do catch it separatly), as it always
		# indicates that there is at least one parameter missing.
		#
		# The following loop is used to parse the given iptables rule string as far as neccessary
		# to act upon it here like creating a chain, flushing (all) chain(s), set policy, append or
		# insert rule or substitute some magic value like a vlan interface.
		try:
			i = 0
			while (i < len (cmd)):
				word = cmd[i]

				# Increment the index here as there are plenty places we might just stop
				# this iteration and jump one or two fields ahead. Beware cmd[i] now is
				# the 'next' element!
				i += 1

				# Pointless actions
				if re.match ("-[CDELRSXZ]", word):
					raise RulesetError ("Operation '%s' is pointless in alff.." % word, string)

				# Table specification?
				if word in ("-t", "--table"):
					table = cmd[i]
					i += 1

					if table not in TABLES:
						raise RulesetError ("Invalid table '%s'. Try one of %s." % (table, ", ".join (TABLES)), string)

					continue

				# Commands with chain as paramter
				if re.match ("-[AINP]", word):
					if mode:
						raise RulesetError ("Trying to reset command!", string)

					chain = cmd[i]
					i += 1

					# Append
					if word in ("-A", "--append"):
						mode = "A"

					# Insert at beginning
					elif word in ("-I", "--insert"):
						mode = "I"

						# There _may_ be another parameter specifying at which position we should
						# place this rule. ip(6)tables starts counting at 1 we start at 0.
						try:
							insert_at = int (cmd[i]) - 1
						except IndexError:
							# The chain has been the last argument, which is fine.
							pass
						except ValueError:
							# There is another parameter, but it isn't an int value, let's see
							# if it's just another parameter spec, which would be fine, or something
							# unexpected, which we will treat as an error.
							if not cmd[i].startswith ("-"):
								raise RulesetError ("Bad index parameter to insert rule: %s" % cmd[i+1], string)
						else:
							# There was another parameter and it was an int value.
							# Skip it when reading further arguments.
							i += 1

					# Create chain
					elif word in ("-N", "--new"):
						mode = "N"

						if i != len (cmd):
							raise RulesetError ("Trailing garbage after '-N' rule: %s" % " ".join (cmd [i+1:]), string)


					# Set policy
					elif word in ("-P", "--policy"):
						mode = "P"

						# Policy and chain will be validated later
						policy = cmd[i]
						i += 1

					# We already read the next word (the chain) and don't want it to be added
					# to the rule twice.
					continue


				# Flush (optional chain paramter)
				if word in ("-F", "--flush"):
					if mode:
						raise RulesetError ("Trying to reset command!")

					mode = "F"
					try:
						chain = cmd[i]
						i += 1
						if chain not in self.ruleset[protocol][table]["chains"]:
							raise RulesetError ("Cannot flush nonexisting chain '%s'." % chain, string)
					except IndexError:
						# There may be no chain given here, which means we have to flush the
						# entire table, which we happily will do.
						pass


				# Special magic
				# <vlan:XYZ>
				if word in ("-i", "--in-interface", "-o", "--out-interface"):
					iface = cmd[i]
					i += 1

					match = re.match ("^<vlan:(.*)>$", iface)
					if match:
						vlan = match.group (1)
						iface = self.config.get_vlan_interface (vlan, self.site, False)

						if not iface:
							raise RulesetError ("Failed to lookup interface for vlan %s at site %s." % (vlan, self.site), string)

					rule += " %s %s" % (word, iface)
					continue


				# Stop parsing the line if we hit a comment at the end of the line
				if word == "#":
					break

				# If we reach this line, it's just some rule specification we don't have to
				# act upon, so just store it.
				rule += " %s" % word
		except IndexError:
			raise RulesetError ("Premature end of arguments..", string)


		#
		# Here we have a valid protocol, table, and some rule spec (which may be an empty string).
		# Validate mode here and go on to the actions which will validate the chain name and policy
		# if neccessary.
		#
		if not mode:
			raise RulesetError ("Rule is lacking some mode (-[AFINP])..", string)


		table_dict = self.ruleset[protocol][table]

		# Flush
		if mode == "F":
			chains = table_dict["chains"]
			if chain:
				if chain not in chains:
					raise RulesetError ("Chain '%s' does not exist, you may want to create it." % chain, string)

				table_dict["num_rules"] -= len (chains[chain]["rules"])
				chains[chain]["rules"] = []
			else:
				for chain in chains.keys ():
					if chain not in DEFAULT_CHAINS[table]:
						table_dict["num_rules"] -= len (chains[chain]["rules"])
						chains[chain]["rules"] = []
			return

		# Create
		elif mode == "N":
			self.create_chain (protocol, chain, table)
			return


		# Chain already existant?
		if chain not in self.ruleset[protocol][table]["chains"]:
			raise RulesetError ("Chain '%s' does not exist, you may want to create it." % chain, string)

		# Policy
		if mode == "P":
			if policy not in ("ACCEPT", "DROP"):
				raise RulesetError ("Invalid policy '%s'. Expected 'ACCEPT' or 'DROP'." % policy, string)

			if self.ruleset[protocol][table]["chains"][chain]["policy"] == "-":
				raise RulesetError ("Trying to set policy for user-defined chain!", string)

			self.ruleset[protocol][table]["chains"][chain]["policy"] = policy
			return

		rule = "-A %s" % chain + rule

		# Append
		if mode == "A":
			self.ruleset[protocol][table]["chains"][chain]["rules"].append (rule)
			self.ruleset[protocol][table]["num_rules"] += 1

		# Insert
		elif mode == "I":
			self.ruleset[protocol][table]["chains"][chain]["rules"].insert (insert_at, rule)
			self.ruleset[protocol][table]["num_rules"] += 1


	def add_rules_from_file (self, path):
		try:
			with open (path, "r") as f:
				for line in f.readlines ():
					# Ignore empty lines and comments starting with #
					if not re.match ("^\s*$\|^\s*#", line):
						self.add_rule (line)
		except IOError as i:
			raise RulesetError ("Error while reading rules from file '%s': %s" % (path, i))


	def save_ruleset (self, protocol):
		protocol = _proto_to_int (protocol)
		if protocol not in self.ruleset:
			raise AlffError ("I don't have a ruleset for protocol '%s'. Try one of %s." % (protocol, ", ".join (self.ruleset.keys ())))

		filename = "%s/%s_%s.rules" % (self.rules_dir, self.site, protocol)

		try:
			fh = open (filename, "w")
		except Exception as i:
			raise RulesetError ("Error while opening rules file '%s': %s" % (filename, i))


		for table in TABLES:
			table_dict = self.ruleset[protocol][table]

			# If there are no rules at all in this table, skip it,
			# but print filter table in any case.
			if table != "filter" and table_dict["num_rules"] == 0:
				continue

			fh.write ("# Generated by alff %s on %s\n" % ('2.0-rc1', now ()))
			fh.write ("*%s\n" % table)

			chains_dict = table_dict["chains"]
			chains = sorted (chains_dict.keys ())

			for chain in chains:
				policy = chains_dict[chain]["policy"]

				# If this is a user created chain, we may want to omit it, if it's empty
				if policy == "-" and self.suppress_empty_chains:
					continue

				fh.write (":%s %s [0:0]\n" % (chain, policy))

			for chain in chains:
				for rule in chains_dict[chain]["rules"]:
					fh.write (rule + "\n")

			fh.write ("COMMIT\n")
			fh.write ("# Completed on %s\n" % now ())


def _proto_to_int (protocol):
	try:
		return int (protocol)
	except ValueError:
		raise RulesetError ("Invalid protocol '%s'. Expected '4' or '6'")
