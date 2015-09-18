#!/bin/bash
# OpenVPN road warrior installer for Debian, Ubuntu and CentOS

# This script will work on Debian, Ubuntu, CentOS and probably other distros
# of the same families, although no support is offered for them. It isn't
# bulletproof but it will probably work if you simply want to setup a VPN on
# your Debian/Ubuntu/CentOS box. It has been designed to be as unobtrusive and
# universal as possible.


if [[ "$USER" != 'root' ]]; then
	echo "Sorry, you need to run this as root"
	exit
fi


if [[ ! -e /dev/net/tun ]]; then
	echo "TUN/TAP is not available"
	exit
fi


if grep -qs "CentOS release 5" "/etc/redhat-release"; then
	echo "CentOS 5 is too old and not supported"
	exit
fi

if [[ -e /etc/debian_version ]]; then
	OS=debian
	RCLOCAL='/etc/rc.local'
elif [[ -e /etc/centos-release || -e /etc/redhat-release ]]; then
	OS=centos
	RCLOCAL='/etc/rc.d/rc.local'
	# Needed for CentOS 7
	chmod +x /etc/rc.d/rc.local
else
	echo "Looks like you aren't running this installer on a Debian, Ubuntu or CentOS system"
	exit
fi

newclient () {
	# Local client
	mkdir -p ~/ovpn/
	cp /etc/openvpn/client-common.txt ~/ovpn/"$1"_local.ovpn
	echo "route-nopull" >> ~/ovpn/"$1"_local.ovpn
	echo "route remote_host 255.255.255.255 net_gateway" >> ~/ovpn/"$1"_local.ovpn
	echo "route 172.16.64.0 255.255.255.0 vpn_gateway" >> ~/ovpn/"$1"_local.ovpn
	if [[ -f /etc/openvpn/server443.conf ]]; then
		echo "route 172.16.65.0 255.255.255.0 vpn_gateway" >> ~/ovpn/"$1"_local.ovpn
	fi
	echo "<ca>" >> ~/ovpn/"$1"_local.ovpn
	cat /etc/openvpn/easy-rsa/pki/ca.crt >> ~/ovpn/"$1"_local.ovpn
	echo "</ca>" >> ~/ovpn/"$1"_local.ovpn
	echo "<cert>" >> ~/ovpn/"$1"_local.ovpn
	cat /etc/openvpn/easy-rsa/pki/issued/$1.crt >> ~/ovpn/"$1"_local.ovpn
	echo "</cert>" >> ~/ovpn/"$1"_local.ovpn
	echo "<key>" >> ~/ovpn/"$1"_local.ovpn
	cat /etc/openvpn/easy-rsa/pki/private/$1.key >> ~/ovpn/"$1"_local.ovpn
	echo "</key>" >> ~/ovpn/"$1"_local.ovpn
	# Internet client
	cp /etc/openvpn/client-common.txt ~/ovpn/"$1"_inter.ovpn
	echo "<ca>" >> ~/ovpn/"$1"_inter.ovpn
	cat /etc/openvpn/easy-rsa/pki/ca.crt >> ~/ovpn/"$1"_inter.ovpn
	echo "</ca>" >> ~/ovpn/"$1"_inter.ovpn
	echo "<cert>" >> ~/ovpn/"$1"_inter.ovpn
	cat /etc/openvpn/easy-rsa/pki/issued/$1.crt >> ~/ovpn/"$1"_inter.ovpn
	echo "</cert>" >> ~/ovpn/"$1"_inter.ovpn
	echo "<key>" >> ~/ovpn/"$1"_inter.ovpn
	cat /etc/openvpn/easy-rsa/pki/private/$1.key >> ~/ovpn/"$1"_inter.ovpn
	echo "</key>" >> ~/ovpn/"$1"_inter.ovpn
}

# Copy udp server config and convert to 443 ssl server config
gensslserver() {
	cp -f /etc/openvpn/server.conf /etc/openvpn/server443.conf
	sed -i "s|port 1194|port 443|" /etc/openvpn/server443.conf
	sed -i "s|proto udp|proto tcp|" /etc/openvpn/server443.conf
	sed -i "s|server 172.16.64.0 255.255.255.0|server 172.16.65.0 255.255.255.0|" /etc/openvpn/server443.conf
	sed -i "s|ifconfig-pool-persist ipp.txt|ifconfig-pool-persist ipp443.txt|" /etc/openvpn/server443.conf
}

# Try to get our IP from the system and fallback to the Internet.
# I do this to make the script compatible with NATed servers (lowendspirit.com)
# and to avoid getting an IPv6.
IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
if [[ "$IP" = "" ]]; then
		IP=$(wget -qO- ipv4.icanhazip.com)
fi


if [[ -e /etc/openvpn/server.conf ]]; then
	while :
	do
	clear
		echo "Looks like OpenVPN is already installed"
		echo ""
		echo "What do you want to do?"
		echo "   1) Add a cert for a new user"
		echo "   2) Revoke existing user cert"
		echo "   3) Remove OpenVPN"
		echo "   4) Exit"
		read -p "Select an option [1-4]: " option
		case "$option" in
			1) 
			echo ""
			echo "Tell me a name for the client cert"
			echo "Please, use one word only, no special characters"
			read -p "Client name: " -e -i client CLIENT
			read -p "Client COUNTRY: " -e -i "TH" CLIENT_COUNTRY
			read -p "Client PROVINCE: " -e -i "Khon Kaen" CLIENT_PROVINCE
			read -p "Client CITY: " -e -i "Muang" CLIENT_CITY
			read -p "Client ORG: " -e -i "Dynamic Dev Co., Ltd." CLIENT_ORG
			read -p "Client OU: " -e -i "Developer" CLIENT_OU
			read -p "Client EMAIL: " -e -i "user@domain.com" CLIENT_EMAIL
			read -p "Client Cert expire time: " -e -i "365" CLIENT_EXPIRE
			cd /etc/openvpn/easy-rsa/
			./easyrsa --dn-mode=org --days="$CLIENT_EXPIRE" --req-cn="$CLIENT" --req-c="$CLIENT_COUNTRY" --req-st="$CLIENT_PROVINCE" --req-city="$CLIENT_CITY" --req-org="$CLIENT_ORG" --req-email="$CLIENT_EMAIL" --req-ou="$CLIENT_OU" build-client-full "$CLIENT" nopass
			# Generates the custom client.ovpn
			newclient "$CLIENT"
			echo ""
			echo "Client $CLIENT added, certs available at ~/ovpn/$CLIENT.ovpn"
			exit
			;;
			2)
			# This option could be documented a bit better and maybe even be simplimplified
			# ...but what can I say, I want some sleep too
			NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
			if [[ "$NUMBEROFCLIENTS" = '0' ]]; then
				echo ""
				echo "You have no existing clients!"
				exit
			fi
			echo ""
			echo "Select the existing client certificate you want to revoke"
			tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
			if [[ "$NUMBEROFCLIENTS" = '1' ]]; then
				read -p "Select one client [1]: " CLIENTNUMBER
			else
				read -p "Select one client [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
			fi
			CLIENT=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
			cd /etc/openvpn/easy-rsa/
			./easyrsa --batch revoke "$CLIENT"
			./easyrsa gen-crl
			# And restart
			if pgrep systemd-journal; then
				systemctl restart openvpn@server.service
			else
				if [[ "$OS" = 'debian' ]]; then
					/etc/init.d/openvpn restart
				else
					service openvpn restart
				fi
			fi
			echo ""
			echo "Certificate for client $CLIENT revoked"
			exit
			;;
			3) 
			echo ""
			read -p "Do you really want to remove OpenVPN? [y/n]: " -e -i n REMOVE
			if [[ "$REMOVE" = 'y' ]]; then
				PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
				if pgrep firewalld; then
					# Using both permanent and not permanent rules to avoid a firewalld reload.
					firewall-cmd --zone=public --remove-port=$PORT/udp
					firewall-cmd --zone=trusted --remove-source=172.16.64.0/24
					firewall-cmd --permanent --zone=public --remove-port=$PORT/udp
					firewall-cmd --permanent --zone=trusted --remove-source=172.16.64.0/24
				fi
				if [[ "$OS" = 'debian' ]]; then
					apt-get remove --purge -y openvpn openvpn-blacklist
				else
					yum remove openvpn -y
				fi
				rm -rf /etc/openvpn
				rm -rf /usr/share/doc/openvpn*
				echo ""
				echo "OpenVPN removed!"
			else
				echo ""
				echo "Removal aborted!"
			fi
			exit
			;;
			4) exit;;
		esac
	done
else
	clear
	echo 'Welcome to this quick OpenVPN "road warrior" installer'
	echo ""
	# OpenVPN setup and first user creation
	echo "I need to ask you a few questions before starting the setup"
	echo "You can leave the default options and just press enter if you are ok with them"
	echo ""
	echo "First I need to know the IPv4 address of the network interface you want OpenVPN"
	echo "listening to."
	read -p "IP address: " -e -i "$IP" IP
	echo ""
	echo "What port do you want for OpenVPN?"
	read -p "Port: " -e -i 1194 PORT
	echo ""
	echo "Do you want OpenVPN to be available at port 53 too?"
	echo "This can be useful to connect under restrictive networks"
	read -p "Listen at port 53 [y/n]: " -e -i n ALTPORT
	echo ""
	echo "Do you want OpenVPN to be available at port 443 too?"
	echo "This can be useful to connect under restrictive networks"
	read -p "Listen at port 443 [y/n]: " -e -i y SSLPORT
	echo ""
	echo "Do you want to enable internal networking for the VPN?"
	echo "This can allow VPN clients to communicate between them"
	read -p "Allow internal networking [y/n]: " -e -i n INTERNALNETWORK
	echo ""
	echo "Do you want to enable multiple connection for single client cert?"
	read -p "Allow multiple connection for single client cert [y/n]: " -e -i n DUPLICATE_CN
	echo ""
	echo "Do you want to reset iptables?"
	read -p "Reset iptables [y/n]: " -e -i y RESET_IPTABLES
	echo ""
	echo "What DNS do you want to use with the VPN?"
	echo "   1) Current system resolvers"
	echo "   2) Norton ConnectSafe"
	echo "   3) Google Public DNS"
	echo "   4) OpenDNS"
	echo "   5) Level 3"
	echo "   6) Norton ConnectSafe + Google Public DNS"
	read -p "DNS [1-6]: " -e -i 1 DNS
	echo ""
	echo "Tell me detail for server cert"
	echo "Please, use one word only, no special characters"
	read -p "Server COUNTRY: " -e -i "TH" SERVER_COUNTRY
	read -p "Server PROVINCE: " -e -i "Khon Kaen" SERVER_PROVINCE
	read -p "Server CITY: " -e -i "Muang" SERVER_CITY
	read -p "Server ORG: " -e -i "Dynamic Dev Co., Ltd." SERVER_ORG
	read -p "Server OU: " -e -i "Server" SERVER_OU
	read -p "Server Admin EMAIL: " -e -i "admin@domain.com" SERVER_EMAIL
	echo ""
	echo "Finally, tell me your name for the client cert"
	echo "Please, use one word only, no special characters"
	read -p "Client name: " -e -i client CLIENT
	read -p "Client COUNTRY: " -e -i "TH" CLIENT_COUNTRY
	read -p "Client PROVINCE: " -e -i "Khon Kaen" CLIENT_PROVINCE
	read -p "Client CITY: " -e -i "Muang" CLIENT_CITY
	read -p "Client ORG: " -e -i "Dynamic Dev Co., Ltd." CLIENT_ORG
	read -p "Client OU: " -e -i "Developer" CLIENT_OU
	read -p "Client EMAIL: " -e -i "user@domain.com" CLIENT_EMAIL
	read -p "Client Cert expire time: " -e -i "365" CLIENT_EXPIRE
	echo ""
	echo "Okay, that was all I needed. We are ready to setup your OpenVPN server now"
	read -n1 -r -p "Press any key to continue..."
		if [[ "$OS" = 'debian' ]]; then
		apt-get update
		apt-get install openvpn iptables openssl -y
	else
		# Else, the distro is CentOS
		yum install epel-release -y
		yum install openvpn iptables openssl wget -y
	fi
	# An old version of easy-rsa was available by default in some openvpn packages
	if [[ -d /etc/openvpn/easy-rsa/ ]]; then
		rm -rf /etc/openvpn/easy-rsa/
	fi
	# Get easy-rsa
	wget --no-check-certificate -O ~/EasyRSA-3.0.0.tgz https://github.com/OpenVPN/easy-rsa/releases/download/3.0.0/EasyRSA-3.0.0.tgz
	tar xzf ~/EasyRSA-3.0.0.tgz -C ~/
	mv ~/EasyRSA-3.0.0/ /etc/openvpn/
	mv /etc/openvpn/EasyRSA-3.0.0/ /etc/openvpn/easy-rsa/
	chown -R root:root /etc/openvpn/easy-rsa/
	rm -rf ~/EasyRSA-3.0.0.tgz
	cd /etc/openvpn/easy-rsa/
	# Create the PKI, set up the CA, the DH params and the server + client certificates
	./easyrsa init-pki
	./easyrsa --dn-mode=org --req-c="$SERVER_COUNTRY" --req-st="$SERVER_PROVINCE" --req-city="$SERVER_CITY" --req-org="$SERVER_ORG" --req-email="$SERVER_EMAIL" --req-ou="$SERVER_OU" --batch build-ca nopass
	./easyrsa gen-dh
	./easyrsa --dn-mode=org --req-c="$SERVER_COUNTRY" --req-st="$SERVER_PROVINCE" --req-city="$SERVER_CITY" --req-org="$SERVER_ORG" --req-email="$SERVER_EMAIL" --req-ou="$SERVER_OU" build-server-full server nopass
	./easyrsa --dn-mode=org --days="$CLIENT_EXPIRE" --req-cn="$CLIENT" --req-c="$CLIENT_COUNTRY" --req-st="$CLIENT_PROVINCE" --req-city="$CLIENT_CITY" --req-org="$CLIENT_ORG" --req-email="$CLIENT_EMAIL" --req-ou="$CLIENT_OU" build-client-full "$CLIENT" nopass
	./easyrsa gen-crl
	# Move the stuff we need
	cp pki/ca.crt pki/private/ca.key pki/dh.pem pki/issued/server.crt pki/private/server.key /etc/openvpn
	# Generate server.conf
	echo "port $PORT
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
topology subnet
server 172.16.64.0 255.255.255.0
ifconfig-pool-persist ipp.txt" > /etc/openvpn/server.conf
	echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server.conf
	echo 'push "route 10.0.0.0 255.0.0.0 net_gateway"' >> /etc/openvpn/server.conf
	echo 'push "route 172.16.0.0 255.240.0.0 net_gateway"' >> /etc/openvpn/server.conf
	echo 'push "route 192.168.0.0 255.255.0.0 net_gateway"' >> /etc/openvpn/server.conf
	# DNS
	case "$DNS" in
		1)
		# Obtain the resolvers from resolv.conf and use them for OpenVPN
		grep -v '#' /etc/resolv.conf | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
			echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server.conf
		done
		;;
		2)
		echo 'push "dhcp-option DNS 199.85.127.10"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 199.85.126.10"' >> /etc/openvpn/server.conf
		;;
		3)
		echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server.conf
		;;
		4)
		echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server.conf
		;;
		5)
		echo 'push "dhcp-option DNS 4.2.2.2"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 4.2.2.4"' >> /etc/openvpn/server.conf
		;;
		6)
		echo 'push "dhcp-option DNS 199.85.127.10"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server.conf
		;;
	esac
	if [[ "$DUPLICATE_CN" = 'y' ]]; then
		echo "duplicate-cn" >> /etc/openvpn/server.conf
	fi
	if [[ "$INTERNALNETWORK" = 'y' ]]; then
		echo "client-to-clent" >> /etc/openvpn/server.conf
	else
	echo "keepalive 10 120
auth SHA256
cipher AES-256-CBC
keysize 256
comp-lzo
persist-key
persist-tun
user nobody
group nogroup
status openvpn-status.log
log-append /var/log/openvpn.log
verb 3
crl-verify /etc/openvpn/easy-rsa/pki/crl.pem" >> /etc/openvpn/server.conf
	# Enable net.ipv4.ip_forward for the system
	if [[ "$OS" = 'debian' ]]; then
		sed -i 's|#net.ipv4.ip_forward=1|net.ipv4.ip_forward=1|' /etc/sysctl.conf
	else
		# CentOS 5 and 6
		sed -i 's|net.ipv4.ip_forward = 0|net.ipv4.ip_forward = 1|' /etc/sysctl.conf
		# CentOS 7
		if ! grep -q "net.ipv4.ip_forward=1" "/etc/sysctl.conf"; then
			echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
		fi
	fi
	# Avoid an unneeded reboot
	echo 1 > /proc/sys/net/ipv4/ip_forward
	# Reset iptable if needed
	if [[ "$RESET_IPTABLES" = 'y' ]]; then
		iptables -F
		iptables -X
		iptables -t nat -F
		iptables -t nat -X
		iptables -t mangle -F
		iptables -t mangle -X
		iptables -P INPUT ACCEPT
		iptables -P FORWARD DROP
		iptables -P OUTPUT ACCEPT
		iptables -I INPUT -p udp --dport "$PORT" -j ACCEPT
		iptables -I FORWARD -i tun+ -j ACCEPT
		iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
		iptables -A POSTROUTING -j MASQUERADE
	fi
	# Set NAT for the VPN subnet
	if [[ "$INTERNALNETWORK" = 'y' ]]; then
		iptables -A POSTROUTING -j MASQUERADE
	else
		iptables -t nat -I POSTROUTING -s 172.16.64.0/24 -j SNAT --to "$IP"
		if [[ "$SSLPORT" = 'y' ]]; then
			iptables -t nat -I POSTROUTING -s 172.16.65.0/24 -j SNAT --to "$IP"
		fi
		iptables -A POSTROUTING -j MASQUERADE
	fi
	if pgrep firewalld; then
		# We don't use --add-service=openvpn because that would only work with
		# the default port. Using both permanent and not permanent rules to
		# avoid a firewalld reload.
		firewall-cmd --zone=public --add-port=$PORT/udp
		firewall-cmd --zone=trusted --add-source=172.16.64.0/24		
		firewall-cmd --permanent --zone=public --add-port=$PORT/udp
		firewall-cmd --permanent --zone=trusted --add-source=172.16.64.0/24
		if [[ "$SSLPORT" = 'y' ]]; then
			firewall-cmd --zone=trusted --add-source=172.16.65.0/24
			firewall-cmd --permanent --zone=trusted --add-source=172.16.65.0/24
		fi
	fi
	if ([iptables -L | grep -q REJECT] || [iptables -L | grep -q DROP]) && [[ "$RESET_IPTABLES" = 'n' ]]; then
		# If iptables has at least one BLOCK rule, we asume this is needed.
		# Not the best approach but I can't think of other and this shouldn't
		# cause problems.
		iptables -I INPUT -p udp --dport "$PORT" -j ACCEPT
		iptables -I FORWARD -i tun+ -j ACCEPT
		iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
	fi
	# Listen at port 53 too if user wants that
	if [[ "$ALTPORT" = 'y' ]]; then
		iptables -t nat -A PREROUTING -p udp -d "$IP" --dport 53 -j REDIRECT --to-port "$PORT"
	fi	
	# If user want ssl server
	if [[ "$SSLPORT" = 'y' ]]; then
		iptables -I INPUT -p tcp --dport 443 -j ACCEPT
		gensslserver
	fi
	# Saving iptables permanently
	if [[ "$OS" = 'debian' ]]; then
		mv /etc/network/iptables.up.rules /etc/network/iptables.up.rules.backup
		iptables-save > /etc/network/iptables.up.rules
		mv /etc/iptables.up.rules /etc/iptables.up.rules.backup
		ln -s /etc/network/iptables.up.rules /etc/iptables.up.rules
	else
		iptables-save > /etc/sysconfig/iptables
	fi
	# And finally, restart OpenVPN
	if [[ "$OS" = 'debian' ]]; then
		# Little hack to check for systemd
		if pgrep systemd-journal; then
			systemctl restart openvpn@server.service
		else
			/etc/init.d/openvpn restart
		fi
	else
		if pgrep systemd-journal; then
			systemctl restart openvpn@server.service
			systemctl enable openvpn@server.service
		else
			service openvpn restart
			chkconfig openvpn on
		fi
	fi
	# Try to detect a NATed connection and ask about it to potential LowEndSpirit users
	EXTERNALIP=$(wget -qO- ipv4.icanhazip.com)
	if [[ "$IP" != "$EXTERNALIP" ]]; then
		echo ""
		echo "Looks like your server is behind a NAT!"
		echo ""
		echo "If your server is NATed (LowEndSpirit), I need to know the external IP"
		echo "If that's not the case, just ignore this and leave the next field blank"
		read -p "External IP: " -e USEREXTERNALIP
		if [[ "$USEREXTERNALIP" != "" ]]; then
			IP="$USEREXTERNALIP"
		fi
	fi
	# client-common.txt is created so we have a template to add further users later
	echo "client
dev tun
remote $IP $PORT udp" > /etc/openvpn/client-common.txt
	# If user want 53 server
	if [[ "$ALTPORT" = 'y' ]]; then
		echo "remote $IP 53 udp" >> /etc/openvpn/client-common.txt
	fi
	# If user want ssl server
	if [[ "$SSLPORT" = 'y' ]]; then
		echo "remote $IP 443 tcp" >> /etc/openvpn/client-common.txt
	fi
	echo "server-poll-timeout 4
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA256
cipher AES-256-CBC
keysize 256
comp-lzo
verb 3" >> /etc/openvpn/client-common.txt
	# Generates the custom client.ovpn
	newclient "$CLIENT"
	echo ""
	echo "Finished!"
	echo ""
	echo "Your client config is available at ~/ovpn/$CLIENT.ovpn"
	echo "If you want to add more clients, you simply need to run this script another time!"
fi
