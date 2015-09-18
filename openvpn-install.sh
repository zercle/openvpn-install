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
	# Generates the client.ovpn
	mkdir -p ~/ovpn/
	cp /usr/share/doc/openvpn*/*ample*/sample-config-files/client.conf ~/ovpn/"$1".ovpn
	sed -i "/ca ca.crt/d" ~/ovpn/"$1".ovpn
	sed -i "/cert client.crt/d" ~/ovpn/"$1".ovpn
	sed -i "/key client.key/d" ~/ovpn/"$1".ovpn
	echo "<ca>" >> ~/ovpn/"$1".ovpn
	cat /etc/openvpn/easy-rsa/2.0/keys/ca.crt >> ~/ovpn/"$1".ovpn
	echo "</ca>" >> ~/ovpn/"$1".ovpn
	echo "<cert>" >> ~/ovpn/"$1".ovpn
	cat /etc/openvpn/easy-rsa/2.0/keys/$1.crt >> ~/ovpn/"$1".ovpn
	echo "</cert>" >> ~/ovpn/"$1".ovpn
	echo "<key>" >> ~/ovpn/"$1".ovpn
	cat /etc/openvpn/easy-rsa/2.0/keys/$1.key >> ~/ovpn/"$1".ovpn
	echo "</key>" >> ~/ovpn/"$1".ovpn
}

# Copy udp server config and convert to 443 ssl server config
gensslserver() {
	cp -f /etc/openvpn/server.conf /etc/openvpn/server443.conf
	sed -i "s|port 1194|port 443|" /etc/openvpn/server443.conf
	sed -i "s|proto udp|proto tcp|" /etc/openvpn/server443.conf
	sed -i "s|172.16.69.0|172.16.69.128|" /etc/openvpn/server443.conf
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
		echo "What do you want to do?"
		echo "   1) Add a cert for a new user"
		echo "   2) Revoke existing user cert"
		echo "   3) Remove OpenVPN"
		echo "   4) Exit"
		read -p "Select an option [1-4]: " option
		case $option in
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
			cd /etc/openvpn/easy-rsa/2.0/
			source ./vars
			# build-key for the client
			export KEY_COUNTRY="$CLIENT_COUNTRY"
			export KEY_PROVINCE="$CLIENT_PROVINCE"
			export KEY_CITY="$CLIENT_CITY"
			export KEY_ORG="$CLIENT_ORG"
			export KEY_OU="$CLIENT_OU"
			export KEY_EMAIL="$CLIENT_EMAIL"
			export KEY_CN="$CLIENT"
			export KEY_EXPIRE="$CLIENT_EXPIRE"
			export EASY_RSA="${EASY_RSA:-.}"
			"$EASY_RSA/pkitool" "$CLIENT"
			# Generate the client.ovpn
			newclient "$CLIENT"
			echo ""
			echo "Client $CLIENT added, certs available at ~/ovpn/$CLIENT.ovpn"
			exit
			;;
			2)
			# Show existing clients list for revoke
			NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/2.0/keys/index.txt | grep "^V" | wc -l)
			if [[ "$NUMBEROFCLIENTS" = '0' ]]; then
				echo ""
				echo "You have no existing clients!"
				exit
			fi
			echo ""
			echo "Select the existing client certificate you want to revoke"
			tail -n +2 /etc/openvpn/easy-rsa/2.0/keys/index.txt | grep "^V" | cut -d '/' -f 7 | cut -d '=' -f 2 | nl -s ') '
			if [[ "$NUMBEROFCLIENTS" = '1' ]]; then
				read -p "Select one client [1]: " CLIENTNUMBER
			else
				read -p "Select one client [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
			fi
			CLIENT=$(tail -n +2 /etc/openvpn/easy-rsa/2.0/keys/index.txt | grep "^V" | cut -d '/' -f 7 | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
			cd /etc/openvpn/easy-rsa/2.0/
			. /etc/openvpn/easy-rsa/2.0/vars
			. /etc/openvpn/easy-rsa/2.0/revoke-full "$CLIENT"
			# If it's the first time revoking a cert, we need to add the crl-verify line
			if ! grep -q "crl-verify" "/etc/openvpn/server.conf"; then
				echo "crl-verify /etc/openvpn/easy-rsa/2.0/keys/crl.pem" >> "/etc/openvpn/server.conf"
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
			fi
			echo ""
			echo "Certificate for client $CLIENT revoked"
			exit
			;;
			3) 
			echo ""
			read -p "Do you really want to remove OpenVPN? [y/n]: " -e -i n REMOVE
			if [[ "$REMOVE" = 'y' ]]; then
				if [[ "$OS" = 'debian' ]]; then
					apt-get remove --purge -y openvpn openvpn-blacklist
				else
					yum remove openvpn -y
				fi
				rm -rf /etc/openvpn
				rm -rf /usr/share/doc/openvpn*
				sed -i '/--dport 53 -j REDIRECT --to-port/d' $RCLOCAL
				sed -i '/iptables -t nat -A POSTROUTING -s 172.16.69.0/d' $RCLOCAL
				sed -i '/iptables -t nat -A POSTROUTING -s 172.16.69.128/d' $RCLOCAL
				sed -i '/iptables -A FORWARD/d' $RCLOCAL
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
	echo "   4) Norton ConnectSafe + Google Public DNS"
	echo "   5) OpenDNS"
	echo "   6) Level 3"
	echo "   7) NTT"
	echo "   8) Hurricane Electric"
	echo "   9) Yandex"
	read -p "DNS [1-9]: " -e -i 1 DNS
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
		apt-get -y install openvpn iptables openssl fail2ban git
		cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
	else
		# Else, the distro is CentOS
		yum install -y epel-release
		yum install -y openvpn iptables openssl wget git
	fi
	# An old version of easy-rsa was available by default in some openvpn packages
	if [[ -d /etc/openvpn/easy-rsa/2.0/ ]]; then
		rm -f /etc/openvpn/easy-rsa/2.0/
	fi
	# Get easy-rsa
	wget -c --no-check-certificate -O ~/easy-rsa.tar.gz https://github.com/OpenVPN/easy-rsa/archive/2.2.2.tar.gz
	tar xzf ~/easy-rsa.tar.gz -C ~/
	mkdir -p /etc/openvpn/easy-rsa/2.0/
	# Copy easy-rsa to openvpn directory
	cp ~/easy-rsa-2.2.2/easy-rsa/2.0/* /etc/openvpn/easy-rsa/2.0/
	# Clear downloaded files
	rm -rf ~/easy-rsa-2.2.2
	rm -rf ~/easy-rsa.tar.gz
	cd /etc/openvpn/easy-rsa/2.0/
	# Let's fix one thing first...
	cp -u -p openssl-1.0.0.cnf openssl.cnf
	# Fuck you NSA - 1024 bits was the default for Debian Wheezy and older
	sed -i 's|export KEY_SIZE=1024|export KEY_SIZE=4096|' /etc/openvpn/easy-rsa/2.0/vars
	# Create the PKI
	. /etc/openvpn/easy-rsa/2.0/vars
	. /etc/openvpn/easy-rsa/2.0/clean-all
	# The following lines are from build-ca. I don't use that script directly
	# because it's interactive and we don't want that. Yes, this could break
	# the installation script if build-ca changes in the future.
	export EASY_RSA="${EASY_RSA:-.}"
	"$EASY_RSA/pkitool" --initca $*
	# Same as the last time, we are going to run build-key-server
	export KEY_COUNTRY="$SERVER_COUNTRY"
	export KEY_PROVINCE="$SERVER_PROVINCE"
	export KEY_CITY="$SERVER_CITY"
	export KEY_ORG="$SERVER_ORG"
	export KEY_OU="$SERVER_OU"
	export KEY_EMAIL="$SERVER_EMAIL"
	export EASY_RSA="${EASY_RSA:-.}"
	"$EASY_RSA/pkitool" --server server
	# Now the client keys. We need to set KEY_CN or the stupid pkitool will cry
	export KEY_COUNTRY="$CLIENT_COUNTRY"
	export KEY_PROVINCE="$CLIENT_PROVINCE"
	export KEY_CITY="$CLIENT_CITY"
	export KEY_ORG="$CLIENT_ORG"
	export KEY_OU="$CLIENT_OU"
	export KEY_EMAIL="$CLIENT_EMAIL"
	export KEY_CN="$CLIENT"
	export KEY_EXPIRE="$CLIENT_EXPIRE"
	export EASY_RSA="${EASY_RSA:-.}"
	"$EASY_RSA/pkitool" "$CLIENT"
	# DH params
	. /etc/openvpn/easy-rsa/2.0/build-dh
	# Let's configure the server
	cd /usr/share/doc/openvpn*/*ample*/sample-config-files
	if [[ "$OS" = 'debian' ]]; then
		gunzip -d server.conf.gz
	fi
	cp server.conf /etc/openvpn/
	cd /etc/openvpn/easy-rsa/2.0/keys
	cp ca.crt ca.key dh4096.pem server.crt server.key /etc/openvpn
	cd /etc/openvpn/
	# Set the server configuration
	sed -i 's|dh dh1024.pem|dh dh4096.pem|' server.conf
	sed -i 's|;push "redirect-gateway def1 bypass-dhcp"|push "redirect-gateway def1 bypass-dhcp"|' server.conf
	sed -i "s|port 1194|port $PORT|" server.conf
	if [[ $"DUPLICATE_CN" = 'y' ]]; then
	sed -i "s|;duplicate-cn|duplicate-cn|" server.conf
	fi	
	sed -i "s|server 10.8.0.0 255.255.255.0|server 172.16.69.0 255.255.255.128|" server.conf
	sed -i "s|;push \"route 192.168.10.0 255.255.255.0\"|push \"route 192.168.0.0 255.255.0.0 net_gateway\"|" server.conf
	sed -i "s|;cipher AES-128-CBC   # AES|cipher AES-256-CBC   # AES|" server.conf
	sed -i "/cipher AES-256-CBC   # AES/i\keysize 256" server.conf
	sed -i "/;tls-auth ta.key 0 # This file is secret/i\auth SHA256" server.conf
	sed -i "s|;log-append  openvpn.log|log-append  /var/log/openvpn.log|" server.conf
	# DNS
	case $DNS in
		1) 
		# Obtain the resolvers from resolv.conf and use them for OpenVPN
		grep -v '#' /etc/resolv.conf | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
			sed -i "/;push \"dhcp-option DNS 208.67.220.220\"/a\push \"dhcp-option DNS $line\"" server.conf
		done
		;;
		2)
		sed -i 's|;push "dhcp-option DNS 208.67.222.222"|push "dhcp-option DNS 199.85.127.10"|' server.conf
		sed -i 's|;push "dhcp-option DNS 208.67.220.220"|push "dhcp-option DNS 199.85.126.10"|' server.conf
		;;
		3)
		sed -i 's|;push "dhcp-option DNS 208.67.222.222"|push "dhcp-option DNS 8.8.4.4"|' server.conf
		sed -i 's|;push "dhcp-option DNS 208.67.220.220"|push "dhcp-option DNS 8.8.8.8"|' server.conf
		;;
		4)
		sed -i 's|;push "dhcp-option DNS 208.67.222.222"|push "dhcp-option DNS 199.85.127.10"|' server.conf
		sed -i 's|;push "dhcp-option DNS 208.67.220.220"|push "dhcp-option DNS 8.8.4.4"|' server.conf
		;;
		5)
		sed -i 's|;push "dhcp-option DNS 208.67.222.222"|push "dhcp-option DNS 208.67.222.222"|' server.conf
		sed -i 's|;push "dhcp-option DNS 208.67.220.220"|push "dhcp-option DNS 208.67.220.220"|' server.conf
		;;
		6) 
		sed -i 's|;push "dhcp-option DNS 208.67.222.222"|push "dhcp-option DNS 4.2.2.2"|' server.conf
		sed -i 's|;push "dhcp-option DNS 208.67.220.220"|push "dhcp-option DNS 4.2.2.4"|' server.conf
		;;
		7) 
		sed -i 's|;push "dhcp-option DNS 208.67.222.222"|push "dhcp-option DNS 129.250.35.250"|' server.conf
		sed -i 's|;push "dhcp-option DNS 208.67.220.220"|push "dhcp-option DNS 129.250.35.251"|' server.conf
		;;
		8) 
		sed -i 's|;push "dhcp-option DNS 208.67.222.222"|push "dhcp-option DNS 74.82.42.42"|' server.conf
		;;
		9) 
		sed -i 's|;push "dhcp-option DNS 208.67.222.222"|push "dhcp-option DNS 77.88.8.8"|' server.conf
		sed -i 's|;push "dhcp-option DNS 208.67.220.220"|push "dhcp-option DNS 77.88.8.1"|' server.conf
		;;
	esac
	# Listen at port 53 too if user wants that
	if [[ "$ALTPORT" = 'y' ]]; then
		iptables -t nat -A PREROUTING -p udp -d $IP --dport 53 -j REDIRECT --to-port "$PORT"
		sed -i "1 a\iptables -t nat -A PREROUTING -p udp -d $IP --dport 53 -j REDIRECT --to-port $PORT" $RCLOCAL
	fi
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
	# Set iptables
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
	fi
	if [[ "$INTERNALNETWORK" = 'y' ]]; then
		iptables -t nat -A POSTROUTING -s 172.16.69.0/25 ! -d 172.16.69.0/25 -j SNAT --to "$IP"
		sed -i "1 a\iptables -t nat -A POSTROUTING -s 172.16.69.0/25 ! -d 172.16.69.0/25 -j SNAT --to $IP" $RCLOCAL
	else
		iptables -t nat -A POSTROUTING -s 172.16.69.0/24 -j SNAT --to "$IP"
		sed -i "1 a\iptables -t nat -A POSTROUTING -s 172.16.69.0/24 -j SNAT --to $IP" $RCLOCAL
	fi
	iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
	sed -i "1 a\iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" $RCLOCAL
	# If user want ssl server
	if [[ "$SSLPORT" = 'y' ]]; then
		gensslserver
	fi
	# And finally, restart OpenVPN
	if [[ "$OS" = 'debian' ]]; then
		# Little hack to check for systemd
		if pgrep systemd-journal; then
			systemctl restart openvpn@server.service
			systemctl restart fail2ban
		else
			/etc/init.d/openvpn restart
			/etc/init.d/fail2ban restart
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
	# Try to detect a NATed connection and ask about it to potential LowEndSpirit
	# users
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
	# IP/port set on the default client.conf so we can add further users
	# without asking for them
	sed -i "s|proto udp|;proto udp|" /usr/share/doc/openvpn*/*ample*/sample-config-files/client.conf
	sed -i "s|remote my-server-1 1194|remote $IP $PORT udp|" /usr/share/doc/openvpn*/*ample*/sample-config-files/client.conf
	sed -i "/resolv-retry infinite/i\server-poll-timeout 4" /usr/share/doc/openvpn*/*ample*/sample-config-files/client.conf
	sed -i "s|;cipher x|cipher AES-256-CBC   # AES|" /usr/share/doc/openvpn*/*ample*/sample-config-files/client.conf
	sed -i "/cipher AES-256-CBC   # AES/i\keysize 256" /usr/share/doc/openvpn*/*ample*/sample-config-files/client.conf
	sed -i "/;tls-auth ta.key 1/i\auth SHA256" /usr/share/doc/openvpn*/*ample*/sample-config-files/client.conf
	# If user want 53 server
	if [[ "$ALTPORT" = 'y' ]]; then
		sed -i "/;remote my-server-2 1194/i\remote $IP 53 udp" /usr/share/doc/openvpn*/*ample*/sample-config-files/client.conf
	fi
	# If user want ssl server
	if [[ "$SSLPORT" = 'y' ]]; then
		sed -i "s|;remote my-server-2 1194|remote $IP 443 tcp|" /usr/share/doc/openvpn*/*ample*/sample-config-files/client.conf
	fi
	# Generate the client.ovpn
	newclient "$CLIENT"
	echo ""
	echo "Finished!"
	echo ""
	echo "Your client config is available at ~/ovpn/$CLIENT.ovpn"
	echo "If you want to add more clients, you simply need to run this script another time!"
fi
