#!/bin/bash

LOCAL_ADDRESS_TUNNEL="$1"
REMOTE_ADDRESS_TUNNEL="$2"
REMOTE_SUBNET="$3"
TUNNEL_NAME="$4"

# Print added address and route
/sbin/ip addr add $LOCAL_ADDRESS_TUNNEL/24 dev $TUNNEL_NAME
/sbin/ip route add $REMOTE_ADDRESS_TUNNEL/32 dev $TUNNEL_NAME advmss 1440

/sbin/ip route add $REMOTE_SUBNET dev $TUNNEL_NAME