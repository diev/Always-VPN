#!/bin/bash -e

# https://github.com/diev/Always-VPN
# based on github.com/jawj/IKEv2-setup
# Copyright (c) 2015 – 2018 George MacKerron
# Released under the MIT licence: http://opensource.org/licenses/mit-license

#DE edition 2019-09-11

echo
echo "=== diev/Always-VPN ==="
echo

function exit_badly {
  echo $1
  exit 1
}

[[ $(lsb_release -rs) == "18.04" ]] || exit_badly "This script is for Ubuntu 18.04 only, aborting (if you know what you're doing, delete this check)."
[[ $(id -u) -eq 0 ]] || exit_badly "Please re-run as root (e.g. sudo ./$0)"

echo "--- Updating and installing software ---"
echo

export DEBIAN_FRONTEND=noninteractive

apt-get -o Acquire::ForceIPv4=true update
apt-get -o Acquire::ForceIPv4=true install -y software-properties-common
add-apt-repository universe
add-apt-repository restricted
add-apt-repository multiverse

apt-get -o Acquire::ForceIPv4=true --with-new-pkgs upgrade -y
apt autoremove -y

apt-get -o Acquire::ForceIPv4=true install -y language-pack-en strongswan libstrongswan-standard-plugins strongswan-libcharon libcharon-standard-plugins libcharon-extra-plugins moreutils iptables-persistent unattended-upgrades dnsutils uuid-runtime git mc

echo
echo "--- Configuration: VPN settings ---"
echo

ETH0ORSIMILAR=$(ip route get 1.1.1.1 | awk -- '{printf $5}')
IP=$(ifdata -pa $ETH0ORSIMILAR)

echo "Network interface: ${ETH0ORSIMILAR}"
echo "External IP: ${IP}"
echo

VPNDNS="1.1.1.1,1.0.0.1"

echo
echo "--- Configuration: general server settings ---"
echo

TZONE="Europe/Moscow"
SSHPORT=22
VPNIPPOOL="192.168.103.0/24"

echo
echo "--- Configuring firewall ---"
echo

iptables -P INPUT   ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT  ACCEPT

iptables -F
iptables -t nat -F
iptables -t mangle -F

# INPUT

# accept anything already accepted
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# accept anything on the loopback interface
iptables -A INPUT -i lo -j ACCEPT

# drop invalid packets
iptables -A INPUT -m state --state INVALID -j DROP

# rate-limit repeated new requests from same IP to any ports
iptables -I INPUT -i $ETH0ORSIMILAR -m state --state NEW -m recent --set
iptables -I INPUT -i $ETH0ORSIMILAR -m state --state NEW -m recent --update --seconds 300 --hitcount 60 -j DROP

# accept (non-standard) SSH
iptables -A INPUT -p tcp --dport $SSHPORT -j ACCEPT

# VPN

# accept IPSec/NAT-T for VPN (ESP not needed with forceencaps, as ESP goes inside UDP)
iptables -A INPUT -p udp --dport  500 -j ACCEPT
iptables -A INPUT -p udp --dport 4500 -j ACCEPT

# forward VPN traffic anywhere
iptables -A FORWARD --match policy --pol ipsec --dir in  --proto esp -s $VPNIPPOOL -j ACCEPT
iptables -A FORWARD --match policy --pol ipsec --dir out --proto esp -d $VPNIPPOOL -j ACCEPT

# reduce MTU/MSS values for dumb VPN clients
iptables -t mangle -A FORWARD --match policy --pol ipsec --dir in -s $VPNIPPOOL -o $ETH0ORSIMILAR -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360

# masquerade VPN traffic over eth0 etc.
iptables -t nat -A POSTROUTING -s $VPNIPPOOL -o $ETH0ORSIMILAR -m policy --pol ipsec --dir out -j ACCEPT  # exempt IPsec traffic from masquerading
iptables -t nat -A POSTROUTING -s $VPNIPPOOL -o $ETH0ORSIMILAR -j MASQUERADE

# fall through to drop any other input and forward traffic

iptables -A INPUT   -j DROP
iptables -A FORWARD -j DROP

iptables -L

debconf-set-selections <<< "iptables-persistent iptables-persistent/autosave_v4 boolean true"
debconf-set-selections <<< "iptables-persistent iptables-persistent/autosave_v6 boolean true"
dpkg-reconfigure iptables-persistent

echo
echo "--- Configuring RSA certificates ---"
echo

cd /tmp
git clone https://github.com/ValdikSS/easy-rsa-ipsec.git
cd easy-rsa-ipsec/easyrsa3
./easyrsa init-pki
./easyrsa --batch --req-cn="${IP} Root CA" build-ca nopass
./easyrsa build-server-full ${IP} nopass
./easyrsa build-client-full ${IP}-user1 nopass
./easyrsa build-client-full ${IP}-user2 nopass
./easyrsa build-client-full ${IP}-user3 nopass
./easyrsa build-client-full ${IP}-user4 nopass
./easyrsa build-client-full ${IP}-user5 nopass
./easyrsa build-client-full ${IP}-user6 nopass
./easyrsa build-client-full ${IP}-user7 nopass
./easyrsa build-client-full ${IP}-user8 nopass
./easyrsa build-client-full ${IP}-user9 nopass
./easyrsa export-p12 ${IP}-user1 nopass
./easyrsa export-p12 ${IP}-user2 nopass
./easyrsa export-p12 ${IP}-user3 nopass
./easyrsa export-p12 ${IP}-user4 nopass
./easyrsa export-p12 ${IP}-user5 nopass
./easyrsa export-p12 ${IP}-user6 nopass
./easyrsa export-p12 ${IP}-user7 nopass
./easyrsa export-p12 ${IP}-user8 nopass
./easyrsa export-p12 ${IP}-user9 nopass
cp pki/ca.crt /etc/ipsec.d/cacerts/
cp pki/issued/${IP}.crt /etc/ipsec.d/certs/
cp pki/private/${IP}.key /etc/ipsec.d/private/

echo
echo "--- Configuring VPN ---"
echo

# ip_forward is for VPN
# ip_no_pmtu_disc is for UDP fragmentation
# others are for security

grep -Fq 'diev/Always-VPN' /etc/sysctl.conf || echo '
# https://github.com/diev/Always-VPN
net.ipv4.ip_forward = 1
net.ipv4.ip_no_pmtu_disc = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
' >> /etc/sysctl.conf

sysctl -p

# ipsec.conf - strongSwan IPsec configuration file
echo "config setup
  uniqueids=never

conn %default
  dpdaction=clear
  dpddelay=35s
  dpdtimeout=300s
  fragmentation=yes
  rekey=no

  left=%any
  leftauth=pubkey
  leftcert=${IP}.crt
  leftsendcert=always
  leftsubnet=0.0.0.0/0

  right=%any
  rightauth=pubkey
  rightdns=${VPNDNS}
  rightsourceip=${VPNIPPOOL}
  rightsendcert=never

conn ikev2-pubkey
  keyexchange=ikev2
  auto=add

conn ikev2-eap-tls
  also=\"ikev2-pubkey\"
  rightauth=eap-tls
  eap_identity=%identity

" > /etc/ipsec.conf

# This file holds shared secrets or RSA private keys for authentication.
echo "${IP} : RSA \"${IP}.key\"

" > /etc/ipsec.secrets

ipsec restart

echo
echo "--- User ---"
echo

# user + SSH

#DE id -u $LOGINUSERNAME &>/dev/null || adduser --disabled-password --gecos "" $LOGINUSERNAME
#DE echo "${LOGINUSERNAME}:${LOGINPASSWORD}" | chpasswd
#DE adduser ${LOGINUSERNAME} sudo
#DE 
#DE sed -r \
#DE -e "s/^#?Port 22$/Port ${SSHPORT}/" \
#DE -e 's/^#?LoginGraceTime (120|2m)$/LoginGraceTime 30/' \
#DE -e 's/^#?PermitRootLogin yes$/PermitRootLogin no/' \
#DE -e 's/^#?X11Forwarding yes$/X11Forwarding no/' \
#DE -e 's/^#?UsePAM yes$/UsePAM no/' \
#DE -i.original /etc/ssh/sshd_config
#DE 
#DE grep -Fq 'diev/Always-VPN' /etc/ssh/sshd_config || echo "
#DE # https://github.com/diev/Always-VPN
#DE MaxStartups 1
#DE MaxAuthTries 2
#DE UseDNS no" >> /etc/ssh/sshd_config
#DE 
#DE service ssh restart

echo
echo "--- Timezone, unattended upgrades ---"
echo

timedatectl set-timezone $TZONE
/usr/sbin/update-locale LANG=en_US.UTF-8

sed -r \
-e 's|^//Unattended-Upgrade::MinimalSteps "true";$|Unattended-Upgrade::MinimalSteps "true";|' \
-e 's|^//Unattended-Upgrade::Mail "root";$|Unattended-Upgrade::Mail "root";|' \
-e 's|^//Unattended-Upgrade::Automatic-Reboot "false";$|Unattended-Upgrade::Automatic-Reboot "true";|' \
-e 's|^//Unattended-Upgrade::Remove-Unused-Dependencies "false";|Unattended-Upgrade::Remove-Unused-Dependencies "true";|' \
-e 's|^//Unattended-Upgrade::Automatic-Reboot-Time "02:00";$|Unattended-Upgrade::Automatic-Reboot-Time "03:00";|' \
-i /etc/apt/apt.conf.d/50unattended-upgrades

echo 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
' > /etc/apt/apt.conf.d/10periodic

service unattended-upgrades restart

echo
echo "--- Creating configuration files ---"
echo

cp pki/ca.crt /tmp/${IP}-ca.crt
cp pki/issued/${IP}.crt /tmp
cp pki/private/*.p12 /tmp

echo
echo "--- How to connect ---"
echo
echo "Connection files take from /tmp"
