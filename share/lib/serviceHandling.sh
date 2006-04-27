#!/usr/bin/env sh
#
# /usr/share/fwrbm/routines/serviceHandling.sh
#
# fwrbm routines for service handlung
#
# Maximilian Wilhelm <mwilhelm@math.uni-paderborn.de>
#  -- Mon, 10 Apr 2006 18:12:03 +0200
#

##
# Check if FILTERED_NETWORKS is set.
# If ${FILTERED_NETWORKS} is empty, we asume that this library was used
# outside fwrbm an exit to avoid trouble.
if [ -z "${FILTERED_NETWORKS}" ]; then
	"Error while loading the fwrbm serviceHandling library: FILTERED_NETWORKS is undefined!" >&2
	exit 1
fi

##
# Create a chain to hook in the entire service rules for serivces that
# should be accessiable from all trusted networks
function allowServicesFromInternalNets() { #{{{
	echo -n " * Creating rules to allow access to services configured to be available from internal networks... "
	iptables -N allowServicesFromInternalNets >/dev/null 2>/dev/null
	for network in ${INTERNAL_NETWORKS}; do
		echo -n "."
		iptables -A FORWARD -s ${network} -j allowServicesFromInternalNets
	done
	echo " done."
}
#}}}

##
# Create a chain to hook in the entire service rules for serivces that
# should be accessiable from all filtered networks
function allowServicesFromFilteredNets() { #{{{
	echo -n " * Creating rules to allow access to services configured to be available from filtered networks... "
	iptables -N allowServicesFromFilteredNets >/dev/null 2>/dev/null
	for network in ${FILTERED_NETWORKS}; do
		echo -n "."
		iptables -A FORWARD -s ${network} -j allowServicesFromFilteredNets
	done
	echo " done."
}
#}}}

##
# Create a chain to hook in the entire service rules for serivces that
# should be accessiable from everywhere in the world
function allowWorldOpenServices() { #{{{
	echo -n " * Creating rule to allow access to services configured to be world-wide available... "
	iptables -N allowWorldOpenServices >/dev/null 2>/dev/null
	iptables -A FORWARD -j allowWorldOpenServices && echo "done. " || echo "FAILED!"
}
#}}}

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
