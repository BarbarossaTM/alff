#!/bin/sh
#
# /etc/init.d/fwrbm
#
# Firewall start/stop script for init
#
# Maximilian Wilhelm <max@rfc2324.org>
#  -- Fri, 03 Feb 2006 11:02:39 +0100
#

# Check if run interactivly or from init
function interactive_run() { #{{{
	if [ -x /bin/readlink ]; then
		tty=`readlink --silent /proc/self/fd/0`
		if [ -z "${tty}" -o "${tty}" == "/dev/console" ]; then
			return 1
		fi
	fi
} #}}}

if [ -f /etc/default/fwrbm ]; then
	. /etc/default/fwrbm
fi

NAME="fwrbm"
DATE="`date +%Y-%m-%d_%H%M`"
		
case "${1}" in
	# Startup fwrbm
	start)
		echo -n "Starting firewall: "
		LOGFILE="/var/log/${NAME}.startup.${DATE}"

		if interactive_run && [ "${FWRBM_INIT_VERBOSE}" == 'true' ]; then
			fwrbm start 2>&1 | tee "${LOGFILE}" && echo "${NAME}." || echo "FAILED!"
		else
			fwrbm start 2>&1 > "${LOGFILE}" && echo "${NAME}." || echo "FAILED!"
		fi

		if [ "${MAIL_LOG}" ]; then
			mail -s "Fwrbm startup log" ${MAIL_LOG} < "${LOGFILE}"
		fi
		;;

	# Stop the while firewall system
	stop)
		echo -n "Stopping firewall: "
		LOGFILE="/var/log/${NAME}.shutdown.${DATE}"

		if interactive_run && [ "${FWRBM_INIT_VERBOSE}" == 'true' ]; then
			fwrbm stop 2>&1 | tee "${LOGFILE}" && echo "${NAME}." || echo "FAILED!"
		else
			fwrbm stop 2>&1 > "${LOGFILE}" && echo "${NAME}." || echo "FAILED!"
		fi

		if [ "${MAIL_LOG}" ]; then
			mail -s "Fwrbm shutdown!" ${MAIL_LOG} < "${LOGFILE}"
		fi
		;;

	# Restart the whole firewall system
	restart)
		$0 stop
		$0 start
		;;

	# Reload services definitions and rules
	reload)
		echo -n "Reload firewall rules: "
		LOGFILE="/var/log/${NAME}.reload.${DATE}"

		if interactive_run && [ "${FWRBM_INIT_VERBOSE}" == 'true' ]; then	
			fwrbm reload 2&>1 | tee "${LOGFILE}" && echo "${NAME}." || echo "FAILED!"
		else
			fwrbm reload 2>&1 > "${LOGFILE}" && echo "${NAME}." || echo "FAILED!"
		fi
		;;
	*)
		echo "Usage: $0 { start | stop | reload | restart }" >&2
		exit 1
		;;
esac

# vim:foldmethod=marker:ft=sh
