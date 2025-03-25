#!/bin/bash
# OpenVPN setup script for SecretBay

# Exit on error
set -e

# Variables
SERVER_IP="{{SERVER_IP}}"
CLIENT_NAME="{{CLIENT_NAME}}"

# Log function
log() {
    echo "[$(date)] $1"
}

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    log "This script must be run as root"
    exit 1
fi

# Update system
log "Updating system packages"
apt-get update
apt-get upgrade -y

# Install OpenVPN and EasyRSA
log "Installing OpenVPN and dependencies"
apt-get install -y openvpn easy-rsa net-tools uuid-runtime

# Setup EasyRSA
log "Setting up EasyRSA"
mkdir -p /etc/openvpn/server/easy-rsa
cp -r /usr/share/easy-rsa/* /etc/openvpn/server/easy-rsa/
cd /etc/openvpn/server/easy-rsa

# Initialize PKI
./easyrsa init-pki

# Build CA without password
log "Building CA and server certificates"
echo -en "\n" | ./easyrsa build-ca nopass

# Generate server certificate without password
echo -en "\n" | ./easyrsa gen-req server nopass
echo -en "yes\n" | ./easyrsa sign-req server server

# Generate Diffie-Hellman parameters
log "Generating Diffie-Hellman parameters (this may take a while)"
./easyrsa gen-dh

# Generate TLS auth key
openvpn --genkey --secret /etc/openvpn/server/ta.key

# Create client certificates
log "Creating client certificates"
echo -en "\n" | ./easyrsa gen-req "${CLIENT_NAME}" nopass
echo -en "yes\n" | ./easyrsa sign-req client "${CLIENT_NAME}"

# Configure server
log "Configuring OpenVPN server"
cat > /etc/openvpn/server/server.conf << EOF
# SecretBay OpenVPN Server Configuration
port 1194
proto udp
dev tun

ca /etc/openvpn/server/easy-rsa/pki/ca.crt
cert /etc/openvpn/server/easy-rsa/pki/issued/server.crt
key /etc/openvpn/server/easy-rsa/pki/private/server.key
dh /etc/openvpn/server/easy-rsa/pki/dh.pem
tls-auth /etc/openvpn/server/ta.key 0

server 10.8.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"

keepalive 10 120
cipher AES-256-GCM
auth SHA256
user nobody
group nogroup
persist-key
persist-tun
status /var/log/openvpn/status.log
verb 3

# Reduce privileged processes
# Cannot use with '--user nobody/--group nogroup
#ncp-ciphers AES-256-GCM:AES-128-GCM
duplicate-cn

# Limit logging
log-append /var/log/openvpn/openvpn.log
mute 20
EOF

# Create log directory
mkdir -p /var/log/openvpn

# Enable IP forwarding
log "Enabling IP forwarding"
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-openvpn.conf
sysctl -p /etc/sysctl.d/99-openvpn.conf

# Configure firewall for NAT
log "Configuring NAT"
# Determine primary network interface
NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)')
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -A INPUT -i tun0 -j ACCEPT
iptables -A FORWARD -i $NIC -o tun0 -j ACCEPT
iptables -A FORWARD -i tun0 -o $NIC -j ACCEPT
iptables -A INPUT -i $NIC -p udp --dport 1194 -j ACCEPT
iptables-save > /etc/iptables/rules.v4

# Enable OpenVPN service
log "Enabling OpenVPN service"
systemctl enable openvpn-server@server
systemctl start openvpn-server@server

# Wait for service to initialize
sleep 3

# Create client configuration with embedded certificates
cat > "/tmp/client.ovpn" << EOF
client
remote ${SERVER_IP} 1194 udp
dev tun
proto udp
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-GCM
auth SHA256
verb 3
<ca>
$(cat /etc/openvpn/server/easy-rsa/pki/ca.crt)
</ca>
<cert>
$(cat /etc/openvpn/server/easy-rsa/pki/issued/${CLIENT_NAME}.crt)
</cert>
<key>
$(cat /etc/openvpn/server/easy-rsa/pki/private/${CLIENT_NAME}.key)
</key>
<tls-auth>
$(cat /etc/openvpn/server/ta.key)
</tls-auth>
key-direction 1
EOF

# Verify OpenVPN is running
if systemctl is-active --quiet openvpn-server@server; then
    log "OpenVPN successfully configured and started"
else
    log "Failed to start OpenVPN"
    exit 1
fi

log "OpenVPN configuration complete"

# Set proper permissions
chmod 644 /tmp/client.ovpn