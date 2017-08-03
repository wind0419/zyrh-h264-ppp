#!/bin/sh
cfgid="$(uci get netset.@netset[0].deviceid)"
imeiid="$(cat /tmp/devimeiid)"

echo "Default" > /tmp/board_info
echo "remote_ip=$(uci get netset.@netset[0].remote_ip)" >> /tmp/board_info
echo "remote_port=$(uci get netset.@netset[0].remote_port)" >> /tmp/board_info
if [ "$cfgid" != "$imeiid" -a "$cfgid" != "" ]; then
	echo "deviceid=$cfgid" >> /tmp/board_info
else
	echo "deviceid=$imeiid" >> /tmp/board_info
	uci set netset.@netset[0].deviceid="$imeiid"
	uci commit
fi

echo "mac=$(cat /sys/class/net/eth0/address)" >> /tmp/board_info
echo "version=$(cat /etc/Version)" >> /tmp/board_info
echo "renewtime=$(date "+%Y-%m-%d %H:%M:%S")" >> /tmp/board_info

/etc/init.d/net4g stop
sleep 3
/etc/init.d/net4g start

