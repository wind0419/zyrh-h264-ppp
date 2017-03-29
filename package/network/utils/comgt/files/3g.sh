#!/bin/sh

[ -n "$INCLUDE_ONLY" ] || {
	NOT_INCLUDED=1
	INCLUDE_ONLY=1

	. ../netifd-proto.sh
	. ./ppp.sh
	init_proto "$@"
}

proto_3g_init_config() {
	no_device=1
	available=1
	ppp_generic_init_config
	proto_config_add_string "device:device"
	proto_config_add_string "apn"
	proto_config_add_string "service"
	proto_config_add_string "pincode"
	proto_config_add_string "dialnumber"
	proto_config_add_string "username"
	proto_config_add_string "password"
	proto_config_add_string "at_port"
	proto_config_add_string "private_dial"
}

proto_3g_setup() {
	local interface="$1"
	local chatcfg

	json_get_var device device
	json_get_var apn apn
	json_get_var service service
	json_get_var pincode pincode
	json_get_var dialnumber dialnumber
	# add by wind
	json_get_var username username
	json_get_var password password
	json_get_var at_port at_port
	json_get_var private_dial private_dial
	# end

	[ -z "$at_port" ] && at_port="/dev/ttyUSB2"
	[ -z "$private_dial" ] && private_dial="0"
	
	[ -n "$dat_device" ] && device=$dat_device
	[ -e "$device" ] || {
		proto_set_available "$interface" 0
		return 1
	}

	nettype="NONE"
	# every time pppd to be called
	case "$service" in
		cdma|evdo)
			chatcfg="/etc/chatscripts/evdo.chat"
		;;
		*)
			rm -f /tmp/dialok
			date >> /tmp/dialcount
			cardinfo=$(gcom -d "$at_port" -s /etc/gcom/getcardinfo.gcom)
			if echo "$cardinfo" | grep -q Novatel; then
				case "$service" in
					umts_only) CODE=2;;
					gprs_only) CODE=1;;
					*) CODE=0;;
				esac
				export MODE="AT\$NWRAT=${CODE},2"
			elif echo "$cardinfo" | grep -q Option; then
				case "$service" in
					umts_only) CODE=1;;
					gprs_only) CODE=0;;
					*) CODE=3;;
				esac
				export MODE="AT_OPSYS=${CODE}"
			elif echo "$cardinfo" | grep -q "Sierra Wireless"; then
				SIERRA=1
			elif echo "$cardinfo" | grep -qi huawei; then
				case "$service" in
					umts_only) CODE="14,2";;
					gprs_only) CODE="13,1";;
					*) CODE="2,2";;
				esac
				export MODE="AT^SYSCFG=${CODE},3FFFFFFF,2,4"
			elif echo "$cardinfo" | grep -q LONGSUNG; then
				case "$service" in
					ulong1) CODE=1;;
					ulong2) CODE=2;;
					ulong3) CODE=3;;
					ulong4) CODE=4;;
					ulong5) CODE=5;;
					ulong6) CODE=6;;
					ulong7) CODE=7;;
					ulong8) CODE=8;;
					ulong9) CODE=9;;
					ulong10) CODE=10;;
					ulong11) CODE=11;;
					ulong12) CODE=12;;
					ulong13) CODE=13;;
					ulong14) CODE=14;;
					ulong15) CODE=15;;
					*) CODE=2;;
				esac
				export MODE="AT+MODODREX=${CODE}"
			else
				#unknow USB_Module
				logger -t ppp "unknow usb module:$cardinfo"
				return 1
			fi

			# check sim card
			local simst=$(gcom -d "$at_port" -s /etc/gcom/checkpin.gcom)
			echo "simcard=$simst" > /tmp/3g-info
			echo $simst > /tmp/sim-info

			if echo "$simst" | grep -qi Ready; then
				# sim card ready.to dial ppp
				[ ! -e "/tmp/sim_ready" ] && touch /tmp/sim_ready
			else
				#SIM ready to no
				rm -f /tmp/sim_ready
				return 1
			fi
			
			local sysinfo=$(gcom -d "$at_port" -s /etc/gcom/sysinfo.gcom)
			if echo "$sysinfo" | grep -qi 'NO,'; then
				logger -t ppp "!!! SYSINFO FAILED !!!"
				# check CSQ  SIMCARD PSRAR  Creg CEREG
				date >> /tmp/at_failed_ret
				gcom -d "$at_port" -s /etc/gcom/check_status.gcom >> /tmp/at_failed_ret
				return 1
			fi
			
			
			nettype=$(gcom -d "$at_port" -s /etc/gcom/nettype.gcom)
			if echo "$nettype" |grep -qw EVDO; then
				username="ctnet@mycdma.cn"
				password="vnet.mobi"
				dialnumber="#777"
			elif echo "$nettype" |grep -qw CDMA; then
				username="ctnet@mycdma.cn"
				password="vnet.mobi"
				dialnumber="#777"
			elif echo "$nettype" |grep -qi NONE; then
				logger -t ppp "Do not find Network!"
				return 1
			else
				if [ "$private_dial" != "1" ]; then
					# ignore web vars
					username=""
					password=""
				fi
				dialnumber="*99#"
			fi
			
			logger -t ppp "Reg Network:$nettype"
			
			chatcfg="/etc/chatscripts/3g.chat"
			connect="DIALNUMBER=$dialnumber /usr/sbin/chat -t5 -v -E -f $chatcfg"
			
			if [ "$private_dial" = "1" ]; then
				chatcfg="/etc/chatscripts/3gprivate.chat"
				#cgdcont ,3GNET CTNET $QCPDPP=1,1,"user","pwd"
				export CGDCONT="AT+CGDCONT=1,\"IP\",\"$apn\"";
				export USER_PWD="AT\$QCPDPP=1,1,\"$password\",\"$username\"";
				gcom -d "$at_port" -s /etc/gcom/initfirst.gcom
				connect="${apn:+USE_APN=$apn} DIALNUMBER=$dialnumber USER=$username PWD=$password /usr/sbin/chat -t5 -v -E -f $chatcfg"
			else
				# auto setting APN
				export USE_APN="$apn";
				gcom -d "$at_port" -s /etc/gcom/autoinitapn.gcom
			fi
			
			# set searching network order
			[ -n "$MODE" ] && gcom -d "$at_port" -s /etc/gcom/setmode.gcom
			
			# close ehrpd and psdialind
			gcom -d "$at_port" -s /etc/gcom/ehrpdclose.gcom
			gcom -d "$at_port" -s /etc/gcom/psdialindclose.gcom
			
			# to check CSQ & Creg & Cops & IMEI & IMSI .etc
			if echo "$cardinfo" | grep -qi IMEI; then
				imei=$(echo "$cardinfo" | grep -i IMEI)
				echo "${imei:15:6}" > /tmp/devimeiid
				echo "imei=${imei#IMEI:}" >> /tmp/3g-info
				imsi=$(gcom -d "$at_port" -s /etc/gcom/getimsi.gcom)
				echo $imsi >> /tmp/3g-info
				sig=$(gcom -d "$at_port" -s /etc/gcom/getstrength.gcom)
				echo "signal=$sig" >> /tmp/3g-info
				echo $sig > /tmp/sig
				echo "mac=$(cat /sys/class/net/eth0/address)" >> /tmp/3g-info
			fi
			
			echo "Default" > /tmp/pub_info
			cat /tmp/3g-info >> /tmp/pub_info
			#cat /tmp/module_status_file >> /tmp/pub_info
			
			echo "Default" > /tmp/dialcfg
			echo "4Gdial=$private_dial" >> /tmp/dialcfg
			echo "apn=$apn" >> /tmp/dialcfg
			echo "user=$username" >> /tmp/dialcfg
			echo "password=$password" >> /tmp/dialcfg
			echo "dialnumber=$dialnumber" >> /tmp/dialcfg
			
			
			#if [ -n "$pincode" ]; then
			#	PINCODE="$pincode" gcom -d "$at_port" -s /etc/gcom/setpin.gcom || {
			#		proto_notify_error "$interface" PIN_FAILED
			#		proto_block_restart "$interface"
			#		return 1
			#	}
			#fi

			# wait for carrier to avoid firmware stability bugs
			#[ -n "$SIERRA" ] && {
			#	gcom -d "$at_port" -s /etc/gcom/getcarrier.gcom || return 1
			#}

		;;
	esac

	ppp_generic_setup "$interface" \
		noaccomp \
		${username:+user "$username" password "$password"} \
		nopcomp \
		novj \
		nobsdcomp \
		noauth \
		lock \
		modem \
		crtscts \
		115200 "$device"
	return 0
}

proto_3g_teardown() {
	proto_kill_command "$interface"
}

[ -z "NOT_INCLUDED" ] || add_protocol 3g
