#!/usr/bin/env sh
#
# /usr/share/alff/routines/serviceHandling.sh
#
# alff routines for service handlung
#
# Maximilian Wilhelm <mwilhelm@math.uni-paderborn.de>
#  -- Mon, 10 Apr 2006 18:12:03 +0200
#

##
# Create a chain to hook in the entire callback service rules for serivces
# that should be able to "call back" into the trusted networks
function allowCBServicesToInternalNets() { #{{{
	echo -n " * Creating rules to allow access from services which \"call back\" to internal networks... "
	iptables -N allowCB_SrvToInternalNets >/dev/null 2>/dev/null
	for network in ${INTERNAL_NETWORKS}; do
		iptables -A FORWARD -d ${network} -j allowCB_SrvToInternalNets && echo -n "."
	done
	echo " done."
}
#}}}

##
# vim:ft=sh:foldmethod=marker:
