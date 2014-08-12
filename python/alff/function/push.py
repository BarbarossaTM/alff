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
#  --  Sat 12 Apr 2014 08:46:44 PM CEST
#

from alff.errors	import *
from alff.function	import *


# argparse configuration
args_config = {
	"_help" : "Push rules to firewalls",
	"site" : {
		"_order" : 1,
		"nargs" : "*",
		"help" : "Site to push rules to",
		"default" : "ALL",
	},

	"fw" : {
		"_order" : 2,
		"nargs" : "*",
		"help" : "Firewall at _site_ to push rules to",
		"default" : "ALL",
	},
}


class Function (BaseFunction):
	pass
