#!/bin/sh

killall dropbear
dropbear -p 222
echo -e "root\nroot" | passwd root
ovsh u Netfilter -w name==v4_lan_ssh_rx rule:="-i BR_LAN -p tcp --destination-port 222"
ovsh u Netfilter -w name==v4_lan_ssh_tx rule:="-o BR_LAN -p tcp --destination-port 222"

sleep 5

iptables -I INPUT -p tcp --dport 222 -j ACCEPT
