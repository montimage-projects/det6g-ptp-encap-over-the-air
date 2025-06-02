

# The following steps need to be done when the Dell laptop is rebooted:
# create ethX dummy NIC
sudo ip link add ethX type dummy
sudo ip addr add 192.168.100.1/24 dev ethX
sudo ip link set ethX up
sudo ip link set dev ethX arp on

# disable offload
sudo /sbin/ethtool --offload ethX rx off tx off sg off


# restart dnsmasq to bind to ethX
# see /etc/dnsmasq.conf
sudo systemctl restart dnsmasq


# reroute traffic to UEs
sudo ip route add 10.200.0.0/24 dev ethX

# enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1
cat /proc/sys/net/ipv4/ip_forward

# setup NAT: from ethX to wlp0s20f3
sudo iptables -t nat -A POSTROUTING -o wlp0s20f3 -j MASQUERADE
sudo iptables -A FORWARD -i wlp0s20f3 -o ethX -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i ethX -o wlp0s20f3 -j ACCEPT


DST_MAC=$(ip neigh show 192.168.100.96 | awk '{print $5}')
# arp of each UE
#sudo arp -s 10.200.0.1 08:00:27:c6:66:c8
#sudo arp -s 10.200.0.2 08:00:27:c6:66:c8
#sudo arp -s 10.200.0.5 08:00:27:c6:66:c8

sudo arp -s 10.200.0.1 $DST_MAC
sudo arp -s 10.200.0.2 $DST_MAC
sudo arp -s 10.200.0.5 $DST_MAC


# optional
# disable ICMP unreachable port
# 1: notify only 1 packet
# 0: completely disable
sudo sysctl -w net.ipv4.icmp_msgs_per_sec=0
cat /proc/sys/net/ipv4/icmp_msgs_per_sec

# optional: disable existing auto timesync services
sudo systemctl stop systemd-timesyncd.service
sudo systemctl stop systemd-timedated.service 


# optional:
# sync laptop timestamp with google
sudo date -s "$(wget -qSO- --max-redirect=0 google.com 2>&1 | grep Date: | cut -d' ' -f5-8)Z"
# sync UE with laptop
bash -x -c 'ssh montimage@raspberry-pi-ue.local sudo date --set @$(date  +%s)'
# sync PTP master with laptop
bash -x -c 'ssh montimage@raspberry-pi-ptp-master.local sudo date --set @$(date  +%s)'
