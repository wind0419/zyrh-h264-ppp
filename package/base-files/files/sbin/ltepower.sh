#!/bin/sh

resetmodule()
{
	echo Init > /tmp/sim-info
    echo 0 > /tmp/sig
    echo 1 > /sys/class/leds/modrst/brightness
	echo "$(date)-repower-4g-module" >> /tmp/repower-4g-module
	echo "$(date)-repower-4g-module" >> /tmp/at_failed_ret
    sleep 5
    echo 0 > /sys/class/leds/modrst/brightness
}

off_leds()
{
	echo none > /sys/class/leds/regstat/trigger
	echo 0 > /sys/class/leds/regstat/brightness

	echo none > /sys/class/leds/dialstatus/trigger
	echo 0 > /sys/class/leds/dialstatus/brightness
}

checkat()
{
	# other process has do at-cmd
	local num="$(ps |grep /etc/gcom |wc -l)"
	[ $num -gt 1 ] && return 1
	gcom -d "$1" -s /etc/gcom/checkpin.gcom > /tmp/sim-info

	num="$(ps |grep /etc/gcom |wc -l)"
	[ $num -gt 1 ] && return 1
	gcom -d "$1" -s /etc/gcom/getstrength.gcom > /tmp/sig

	num="$(ps |grep /etc/gcom |wc -l)"
	[ $num -gt 1 ] && return 1
	gcom -d "$1" -s /etc/gcom/check_status.gcom > /tmp/module_status_file

	if cat /tmp/sim-info | grep -qi 'Ready'; then
		[ ! -e "/tmp/sim_ready" ] && touch /tmp/sim_ready
		# no dialing ; no 3g-ppp; sim-card ok
		ifconfig 3g-ppp | grep -qi 'inet addr:' || /sbin/ifup ppp
	elif ifconfig 3g-ppp | grep -qi 'inet addr:'; then
		# no dialing; 3g-ppp ok' ; sim-card error;  detecting error
		echo Ready > /tmp/sim-info
		[ ! -e "/tmp/sim_ready" ] && touch /tmp/sim_ready
	else
		logger -t ltecheck "Check:SIM-error and ppp failed"
		echo "$(date)-SIM-error and ppp dial failed" >> /tmp/at_failed_ret
		cat /tmp/module_status_file >> /tmp/at_failed_ret
		rm -f /tmp/dialok
	fi
}

rm -rf /tmp/gcom*
# ttyUSBx is not exist
[ ! -e "$1" ] && return 1
[ ! -e "/tmp/cfuncount" ] && echo -n > /tmp/cfuncount
[ ! -e "/tmp/dialcount" ] && echo -n > /tmp/dialcount
[ ! -e "/tmp/at_failed_ret" ] && echo -n > /tmp/at_failed_ret

num="$(cat /tmp/at_failed_ret | wc -l)"
if [ $num -ge 800 ]; then
	echo -n > /tmp/at_failed_ret
fi

if [ -e "/tmp/dialok" ]; then
	checkat "$1"
	echo -n > /tmp/dialcount
	echo -n > /tmp/cfuncount
else
	ifdown ppp
	
	off_leds
	sleep 5
	num="$(cat /tmp/cfuncount | wc -l)"
	if [ $num -ge 3 ]; then
		logger -t ltecheck "cfuncount>3,to reset module"
		#cfun=0
		gcom -d "$1" -s /etc/gcom/clearcfun.gcom
		echo -n > /tmp/dialcount
		echo -n > /tmp/cfuncount
		resetmodule
		sleep 20
		ifup ppp
	else
		num="$(cat /tmp/dialcount | wc -l)"
		if [ $num -ge 5 ]; then
			logger -t ltecheck "dialcount>5,to reset cfun"
			gcom -d "$1" -s /etc/gcom/clearcfun.gcom
			gcom -d "$1" -s /etc/gcom/setcfun.gcom
			echo "$(date)-cfun-reset" >> /tmp/cfuncount
			echo "$(date)-cfun-reset" >> /tmp/at_failed_ret
			echo -n > /tmp/dialcount
			ifup ppp
		else
			logger -t ltecheck "$(date) ppp redial"
			echo "$(date) ppp redial" >> /tmp/at_failed_ret
	        cat /tmp/module_status_file >> /tmp/at_failed_ret
			ifup ppp
		fi
	fi
fi
