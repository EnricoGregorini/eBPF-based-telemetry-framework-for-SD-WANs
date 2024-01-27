#!/bin/bash

addresses_file="/home/bonsai/addresses.txt"
ipsec_conf="/etc/ipsec.conf"
ipsec_secrets="/etc/ipsec.secrets"

# Function to print error and exit
function print_error_and_exit {
    echo "Error: $1"
    exit 1
}


# Check if the addresses file exists
if [ ! -f "$addresses_file" ]; then
    print_error_and_exit "The addresses file '$addresses_file' does not exist."
fi

# Read the addresses from the file
mapfile -t addresses < "$addresses_file"

# Check if the file contains exactly four lines
if [ "${#addresses[@]}" -ne 6 ]; then
    print_error_and_exit "The addresses file must contain exactly 6 lines (local and remote addresses and the same for tunnel addresses) + 2 LAN subnets ip addressing pool."
fi

# Assign addresses to variables
LOCAL_ADDRESS="${addresses[0]}"
REMOTE_ADDRESS="${addresses[1]}"
LOCAL_ADDRESS_TUNNEL="${addresses[2]}"
REMOTE_ADDRESS_TUNNEL="${addresses[3]}"
LOCAL_SUBNET="${addresses[4]}"
REMOTE_SUBNET="${addresses[5]}"

PSK="$1"
TUNNEL_NAME="gre1"

/sbin/ip link delete $TUNNEL_NAME

# GRE Tunnel Setup
/sbin/ip tunnel add $TUNNEL_NAME mode gre remote $REMOTE_ADDRESS local $LOCAL_ADDRESS ttl 255 key 1002
/sbin/ip link set $TUNNEL_NAME up
/sbin/ip link set dev $TUNNEL_NAME mtu 1460


# Print GRE tunnel configuration
/sbin/ip tunnel show $TUNNEL_NAME

# Print information about the GRE tunnel
echo "GRE Tunnel Configuration:"
echo "Local Tunnel Address: $LOCAL_ADDRESS_TUNNEL"
echo "Remote Tunnel Address: $REMOTE_ADDRESS_TUNNEL"


# IPSec Configuration
cat > "$ipsec_conf" <<EOF

conn SD-WAN-tunnel
        authby=secret
        left=%defaultroute
        leftid=$LOCAL_ADDRESS_TUNNEL
        leftsubnet=$LOCAL_SUBNET
        right=$REMOTE_ADDRESS_TUNNEL
        rightsubnet=$REMOTE_SUBNET
        ike=aes256-sha2_256-modp1024!
        esp=aes256-sha2_256!
        keyexchange=ikev1
        keyingtries=0
        ikelifetime=1h
        lifetime=8h
        dpddelay=30
        dpdtimeout=120
        dpdaction=restart
        auto=start
EOF

# IPSec Secrets
echo "$LOCAL_ADDRESS_TUNNEL $REMOTE_ADDRESS_TUNNEL : PSK \"$PSK\"" > "$ipsec_secrets"

# Restart IPSec Service
sudo ipsec stop
sudo ipsec start

# Print IPSec configuration
echo -e "\nIPSec Configuration (Contents of $ipsec_conf):"
cat "$ipsec_conf"

# Print IPSec secrets
echo -e "\nIPSec Secrets (Contents of $ipsec_secrets):"
cat "$ipsec_secrets"

sudo ./create_addr_route.sh $LOCAL_ADDRESS_TUNNEL $REMOTE_ADDRESS_TUNNEL $REMOTE_SUBNET $TUNNEL_NAME
