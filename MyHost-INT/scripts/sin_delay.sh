#!/bin/bash

# Interfaces to configure
INTERFACES=("eth0" "eth1")

# Delay configuration
MIN_DELAY=10
MAX_DELAY=30
STEP=5   # increase or decrease the delay by 5 ms
DELAY=$MIN_DELAY
INCREMENT=true

# Time interval in seconds given as input argument
INTERVAL="$1"   

# Function to apply delay
apply_delay() {
    for IFACE in "${INTERFACES[@]}"; do
        tc qdisc add dev "$IFACE" root netem delay "${DELAY}ms" 2>/dev/null || \
        tc qdisc change dev "$IFACE" root netem delay "${DELAY}ms"
    done
}

# Main loop
while true; do
    apply_delay

    # Check direction of delay change and update delay
    if [ "$INCREMENT" = true ]; then
        if [ $DELAY -eq $MAX_DELAY ]; then
            INCREMENT=false
            DELAY=$((DELAY - STEP))
        else
            DELAY=$((DELAY + STEP))
        fi
    else
        if [ $DELAY -eq $MIN_DELAY ]; then
            INCREMENT=true
            DELAY=$((DELAY + STEP))
        else
            DELAY=$((DELAY - STEP))
        fi
    fi

    sleep $INTERVAL
done
