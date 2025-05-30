#!/bin/bash

PORT_1=ethX
PORT_2=enx00e116000000

function get-mac(){
	iface=$1
	cat /sys/class/net/$iface/address
}

function get-ip(){
	iface=$1
	ip -4 addr show $iface | grep -oP '(?<=inet\s)\d+(\.\d+){3}'
}

#SRC_MAC_1=$(get-mac $PORT_1)
SRC_MAC_1="46:77:a6:33:c4:93"
# MAC inside 5G core VM
#DST_MAC_1="08:00:27:c6:66:c8"
DST_MAC_1="46:77:a6:33:c4:93"


#SRC_IP_1=$(get-ip $PORT_1)
SRC_IP_1="192.168.100.1"
DST_IP_1="10.200.0.1"




SRC_MAC_2=$(get-mac $PORT_2)
DST_MAC_2="01:1b:19:00:00:00"

SRC_IP_2="2.2.2.2" #not important
DST_IP_2="2.2.2.2"

# syntax:
# input_port => output_port srcMac srcIP dstMac dstIp
CFG_1=$(echo "table_add packet_forward set_addresses 2 => 1 $SRC_MAC_1 $SRC_IP_1 $DST_MAC_1 $DST_IP_1")
CFG_2=$(echo "table_add packet_forward set_addresses 1 => 2 $SRC_MAC_2 $SRC_IP_2 $DST_MAC_2 $DST_IP_2")

echo $CFG_1
echo $CFG_2
function config(){
	# wait for the swith starting
	sleep 3
	
	echo $CFG_1 | simple_switch_CLI
	echo $CFG_2 | simple_switch_CLI
	# set switch ID
	echo "table_set_default config_switch set_switch_id 1" | simple_switch_CLI
}

config &

exec sudo /usr/local/bin/simple_switch --log-console --log-level info -i 1@$PORT_1 -i 2@$PORT_2 tc.json
