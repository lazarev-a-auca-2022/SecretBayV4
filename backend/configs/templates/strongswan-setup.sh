#!/bin/bash
# StrongSwan setup script for iOS VPN configuration

# Exit on error
set -e

# Variables
SERVER_IP="{{SERVER_IP}}"
VPN_USERNAME="{{VPN_USERNAME}}"
VPN_PASSWORD="{{VPN_PASSWORD}}"

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

# Install necessary packages
log "Installing required packages"
apt-get install -y strongswan strongswan-pki libcharon-extra-plugins libcharon-extauth-plugins libstrongswan-extra-plugins libstrongswan-standard-plugins moreutils iptables-persistent uuid-runtime

# Generate server certificates
log "Generating server certificates"
mkdir -p /etc/ipsec.d/private /etc/ipsec.d/certs /etc/ipsec.d/cacerts

# Generate CA key and certificate
ipsec pki --gen --type rsa --size 4096 --outform pem > /etc/ipsec.d/private/ca.key.pem
chmod 600 /etc/ipsec.d/private/ca.key.pem

ipsec pki --self --ca --lifetime 3650 --in /etc/ipsec.d/private/ca.key.pem \
    --type rsa --digest sha256 --dn "CN=SecretBay VPN CA" --outform pem > /etc/ipsec.d/cacerts/ca.cert.pem

# Generate server key and certificate
ipsec pki --gen --type rsa --size 4096 --outform pem > /etc/ipsec.d/private/server.key.pem
chmod 600 /etc/ipsec.d/private/server.key.pem

ipsec pki --pub --in /etc/ipsec.d/private/server.key.pem --type rsa \
    | ipsec pki --issue --lifetime 1825 --digest sha256 \
    --cacert /etc/ipsec.d/cacerts/ca.cert.pem --cakey /etc/ipsec.d/private/ca.key.pem \
    --dn "CN=${SERVER_IP}" --san "${SERVER_IP}" \
    --flag serverAuth --flag ikeIntermediate --outform pem \
    > /etc/ipsec.d/certs/server.cert.pem

# Generate client key and certificate
ipsec pki --gen --type rsa --size 4096 --outform pem > /etc/ipsec.d/private/client.key.pem
chmod 600 /etc/ipsec.d/private/client.key.pem

ipsec pki --pub --in /etc/ipsec.d/private/client.key.pem --type rsa \
    | ipsec pki --issue --lifetime 1825 --digest sha256 \
    --cacert /etc/ipsec.d/cacerts/ca.cert.pem --cakey /etc/ipsec.d/private/ca.key.pem \
    --dn "CN=SecretBay VPN Client" \
    --outform pem > /etc/ipsec.d/certs/client.cert.pem

# Export client certificate as PKCS#12
openssl pkcs12 -export -inkey /etc/ipsec.d/private/client.key.pem \
    -in /etc/ipsec.d/certs/client.cert.pem -name "SecretBay VPN Client" \
    -certfile /etc/ipsec.d/cacerts/ca.cert.pem \
    -caname "SecretBay VPN CA" \
    -out /etc/ipsec.d/private/client.p12 \
    -passout pass:

# Generate a random identifier for this VPN
UUID=$(uuidgen)

# Configure StrongSwan
log "Configuring StrongSwan"
cat > /etc/ipsec.conf << EOF
config setup
    charondebug="ike 1, knl 1, cfg 0"
    uniqueids=no

conn ikev2-vpn
    auto=add
    compress=no
    type=tunnel
    keyexchange=ikev2
    fragmentation=yes
    forceencaps=yes
    
    # ECDSA, AES-GCM, PFS ECDH-384
    ike=aes256gcm16-prfsha384-ecp384!
    esp=aes256gcm16-ecp384!
    
    dpdaction=clear
    dpddelay=300s
    rekey=no
    
    left=%any
    leftid=@${SERVER_IP}
    leftcert=server.cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    
    right=%any
    rightid=%any
    rightauth=eap-mschapv2
    rightsourceip=10.10.10.0/24
    rightdns=8.8.8.8,8.8.4.4
    rightsendcert=never
    
    eap_identity=%identity
    
    # Enable IKEv2 mobility
    mobike=yes
EOF

# Configure strongswan.conf
cat > /etc/strongswan.conf << EOF
charon {
    load_modular = yes
    duplicheck.enable = no
    compress = yes
    plugins {
        include strongswan.d/charon/*.conf
    }
    dns1 = 8.8.8.8
    dns2 = 8.8.4.4
    nbns1 = 8.8.8.8
    nbns2 = 8.8.4.4
}

include strongswan.d/*.conf
EOF

# Configure secrets
cat > /etc/ipsec.secrets << EOF
# RSA server.key.pem
: RSA server.key.pem
${VPN_USERNAME} : EAP "${VPN_PASSWORD}"
EOF

chmod 600 /etc/ipsec.secrets

# Configure IP forwarding
log "Configuring IP forwarding"
echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-vpn.conf
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.d/99-vpn.conf
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.d/99-vpn.conf
sysctl -p /etc/sysctl.d/99-vpn.conf

# Configure firewall for NAT
log "Configuring NAT"
iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o $(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)') -j MASQUERADE
iptables-save > /etc/iptables/rules.v4

# Generate iOS mobileconfig
log "Generating iOS mobileconfig"
cat > /tmp/ios-vpn.mobileconfig << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>IKEv2</key>
            <dict>
                <key>AuthenticationMethod</key>
                <string>None</string>
                <key>ChildSecurityAssociationParameters</key>
                <dict>
                    <key>EncryptionAlgorithm</key>
                    <string>AES-256-GCM</string>
                    <key>IntegrityAlgorithm</key>
                    <string>SHA2-256</string>
                    <key>DiffieHellmanGroup</key>
                    <integer>14</integer>
                    <key>LifeTimeInMinutes</key>
                    <integer>1440</integer>
                </dict>
                <key>DeadPeerDetectionRate</key>
                <string>Medium</string>
                <key>DisableMOBIKE</key>
                <integer>0</integer>
                <key>DisableRedirect</key>
                <integer>0</integer>
                <key>EnableCertificateRevocationCheck</key>
                <integer>0</integer>
                <key>EnablePFS</key>
                <integer>0</integer>
                <key>IKESecurityAssociationParameters</key>
                <dict>
                    <key>EncryptionAlgorithm</key>
                    <string>AES-256-GCM</string>
                    <key>IntegrityAlgorithm</key>
                    <string>SHA2-256</string>
                    <key>DiffieHellmanGroup</key>
                    <integer>14</integer>
                    <key>LifeTimeInMinutes</key>
                    <integer>1440</integer>
                </dict>
                <key>LocalIdentifier</key>
                <string>{{VPN_USERNAME}}</string>
                <key>OnDemandEnabled</key>
                <integer>1</integer>
                <key>OnDemandRules</key>
                <array>
                    <dict>
                        <key>Action</key>
                        <string>Connect</string>
                    </dict>
                </array>
                <key>RemoteAddress</key>
                <string>{{SERVER_IP}}</string>
                <key>RemoteIdentifier</key>
                <string>{{SERVER_IP}}</string>
                <key>UseConfigurationAttributeInternalIPSubnet</key>
                <integer>0</integer>
            </dict>
            <key>IPv4</key>
            <dict>
                <key>OverridePrimary</key>
                <integer>1</integer>
            </dict>
            <key>PayloadDescription</key>
            <string>Configures VPN settings</string>
            <key>PayloadDisplayName</key>
            <string>VPN</string>
            <key>PayloadIdentifier</key>
            <string>com.apple.vpn.managed.$(uuidgen)</string>
            <key>PayloadType</key>
            <string>com.apple.vpn.managed</string>
            <key>PayloadUUID</key>
            <string>$(uuidgen)</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>Proxies</key>
            <dict>
                <key>HTTPEnable</key>
                <integer>0</integer>
                <key>HTTPSEnable</key>
                <integer>0</integer>
            </dict>
            <key>UserDefinedName</key>
            <string>SecretBay VPN</string>
            <key>VPNType</key>
            <string>IKEv2</string>
        </dict>
    </array>
    <key>PayloadDisplayName</key>
    <string>SecretBay VPN</string>
    <key>PayloadIdentifier</key>
    <string>com.secretbay.vpn.$(uuidgen)</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>$(uuidgen)</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
EOF

# Restart StrongSwan
log "Restarting StrongSwan"
systemctl restart strongswan-starter

# Verify StrongSwan is running
if systemctl is-active --quiet strongswan-starter; then
    log "StrongSwan successfully configured and started"
else
    log "Failed to start StrongSwan"
    exit 1
fi

log "iOS VPN configuration complete"