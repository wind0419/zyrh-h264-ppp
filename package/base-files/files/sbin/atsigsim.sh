#!/bin/sh

# wait ltepower.sh detect firstly
sleep 3

[ ! -e "$1" ] && return 1
num="$(ps |grep /etc/gcom |wc -l)"
[ $num -gt 1 ] && return 1

[ -e "/tmp/isdialing" ] && return 1

gcom -d "$1" -s /etc/gcom/checkpin.gcom > /tmp/sim-info
gcom -d "$1" -s /etc/gcom/getstrength.gcom > /tmp/sig
gcom -d "$1" -s /etc/gcom/check_status.gcom > /tmp/module_status_file
