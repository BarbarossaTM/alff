#!/bin/sh
#
# Maximilian Wilhelm <max@rfc2324.org>
#  -- Sat, 17 Jun 2006 23:19:08 +0200
#

### BEGIN INIT INFO
# Provides:             alff-agent
# Required-Start:       $network
# Required-Stop:        $network
# Default-Start:        2 3 4 5
# Default-Stop:         0 1 6
# Short-Description:    Alff-Agent start/stop script for init
### END INIT INFO

# Check if run interactivly or from init
function interactive_run() { #{{{
	if [ -x /bin/readlink ]; then
		tty=`readlink --silent /proc/self/fd/0`
		if [ -z "${tty}" -o "${tty}" == "/dev/console" ]; then
			return 1
		fi
	fi
} #}}}

# Flush all chains
function flush_all() { #{{{
	# Reset filter chains #{{{
	iptables -t filter -P INPUT ACCEPT
	iptables -t filter -P OUTPUT ACCEPT
	iptables -t filter -P FORWARD ACCEPT
	iptables -t filter -F
	iptables -t filter -X
	iptables -t filter -Z
	#}}}

	# Reset nat chains #{{{
	iptables -t nat -P PREROUTING ACCEPT
	iptables -t nat -P POSTROUTING ACCEPT
	iptables -t nat -P OUTPUT ACCEPT
	iptables -t nat -F
	iptables -t nat -X
	iptables -t nat -Z
	#}}}

	# Reset mangle chains #{{{
	iptables -t mangle -F
	iptables -t mangle -X
	iptables -t mangle -Z
	#}}}

	# And the same for ipv6
	# Reset filter chains #{{{
	ip6tables -t filter -P INPUT ACCEPT
	ip6tables -t filter -P OUTPUT ACCEPT
	ip6tables -t filter -P FORWARD ACCEPT
	ip6tables -t filter -F
	ip6tables -t filter -X
	ip6tables -t filter -Z
	#}}}

	# Reset mangle chains #{{{
	ip6tables -t mangle -F
	ip6tables -t mangle -X
	ip6tables -t mangle -Z
	#}}}

}
#}}}

# Load current rules via alff-cat
function load_rules() { #{{{
	# First check for an existing DELETE_ME_TOKEN, to be aware of a reboot while
	# alff-cat was running. Maybe something went wrong.
	if [ -f "${DELETE_ME_TOKEN}" ]; then
		echo "It seems that this machine was rebooted while loading new rules or the new" >&2
		echo "rules were not approved. Trying to load the old rules to avoid trouble..." >&2
		if [ -f "${OLD_RULES_FILE}" ]; then
			iptables-restore < "${OLD_RULES_FILE}"
		fi
		if [ -f "${OLD_RULES_FILE_V6}" ]; then
			ip6tables-restore < "${OLD_RULES_FILE_V6}"
		fi

	# OK, everything looks good, just load the ruleset if there is any
	elif [ -f "${CURRENT_RULES_FILE}" -a -f "${CURRENT_RULES_FILE_V6}" ]; then
			iptables-restore < "${CURRENT_RULES_FILE}"
			ip6tables-restore < "${CURRENT_RULES_FILE_V6}"

	# No rules :-(
	else
		echo "Error: No ruleset found."
		exit 1
	fi
}
#}}}

if [ -f /etc/alff/alff-agent.conf ]; then
	. /etc/alff/alff-agent.conf
fi

if [ -s /etc/alff/alff-defaults.conf ]; then
	. /etc/alff/alff-defaults.conf
else
	echo "Error: The alff default configuration does not exist or is empty." >&2
	exit 1
fi


MY_NAME="alff-agent"
DATE="`date +%Y-%m-%d_%H%M`"


case "${1}" in
	# Startup alff
	start)
		echo -n "Starting Alff agent: "
		LOGFILE="/var/log/${MY_NAME}.startup.${DATE}"

		if interactive_run && [ "${ALFF_INIT_VERBOSE}" == 'true' ]; then
			load_rules 2>&1 | tee "${LOGFILE}" && echo "Rules successfully loaded." || echo "FAILED!"
		else
			load_rules 2>&1 > "${LOGFILE}" && echo "Rules successfully loaded." || echo "FAILED!"
		fi

		if [ "${MAIL_TO}" ]; then
			mail -s "Alff agent startup log" ${MAIL_TO} < "${LOGFILE}"
		fi
		;;

	# Stop the whole firewall system
	stop)
		echo -n "Stopping firewall: "
		LOGFILE="/var/log/${MY_NAME}.shutdown.${DATE}"

		if interactive_run; then
			flush_all 2>&1 | tee "${LOGFILE}" && echo "done." || echo "FAILED!"
		else
			flush_all 2>&1 > "${LOGFILE}" && echo "done." || echo "FAILED!"
		fi

		if [ "${MAIL_TO}" ]; then
			mail -s "Alff shutdown!" ${MAIL_TO} < "${LOGFILE}"
		fi
		;;

	# Restart the whole firewall system
	restart)
		$0 stop
		$0 start
		;;

	# Reload services definitions and rules
	reload)
		$0 start
		;;
	*)
		echo "Usage: $0 { start | stop | reload | restart }" >&2
		exit 1
		;;
esac

# vim:foldmethod=marker:ft=sh
