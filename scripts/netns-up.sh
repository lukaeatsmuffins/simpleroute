#!/bin/bash

# Network namespace setup script for AFP testing
# Creates two namespaces (gen, dut) with a veth pair for controlled testing

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
GEN_NS="gen"
DUT_NS="dut"
VETH0="veth0"
VETH1="veth1"
GEN_IP="10.0.0.1/24"
DUT_IP="10.0.0.2/24"

echo -e "${BLUE}=== AFP Network Namespace Setup ===${NC}"
echo "Setting up controlled testing environment..."

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root${NC}"
   echo "Usage: sudo $0"
   exit 1
fi

# Function to check if namespace exists
ns_exists() {
    ip netns list | grep -q "^$1 "
}

# Function to check if veth pair exists
veth_exists() {
    ip link show "$1" >/dev/null 2>&1
}

echo -e "${YELLOW}1. Creating network namespaces...${NC}"

# Create gen namespace (idempotent)
if ns_exists "$GEN_NS"; then
    echo "  ✓ Namespace '$GEN_NS' already exists"
else
    ip netns add "$GEN_NS"
    echo "  ✓ Created namespace '$GEN_NS'"
fi

# Create dut namespace (idempotent)
if ns_exists "$DUT_NS"; then
    echo "  ✓ Namespace '$DUT_NS' already exists"
else
    ip netns add "$DUT_NS"
    echo "  ✓ Created namespace '$DUT_NS'"
fi

echo -e "${YELLOW}2. Setting up veth pair...${NC}"

# Create veth pair (idempotent)
if veth_exists "$VETH0" && veth_exists "$VETH1"; then
    echo "  ✓ Veth pair '$VETH0/$VETH1' already exists"
else
    # Remove existing veth if it exists
    if veth_exists "$VETH0"; then
        ip link delete "$VETH0" 2>/dev/null || true
    fi
    if veth_exists "$VETH1"; then
        ip link delete "$VETH1" 2>/dev/null || true
    fi
    
    # Create new veth pair
    ip link add "$VETH0" type veth peer name "$VETH1"
    echo "  ✓ Created veth pair '$VETH0/$VETH1'"
fi

echo -e "${YELLOW}3. Moving interfaces to namespaces...${NC}"

# Move veth0 to gen namespace (idempotent)
if ip netns exec "$GEN_NS" ip link show "$VETH0" >/dev/null 2>&1; then
    echo "  ✓ '$VETH0' already in namespace '$GEN_NS'"
else
    ip link set "$VETH0" netns "$GEN_NS"
    echo "  ✓ Moved '$VETH0' to namespace '$GEN_NS'"
fi

# Move veth1 to dut namespace (idempotent)
if ip netns exec "$DUT_NS" ip link show "$VETH1" >/dev/null 2>&1; then
    echo "  ✓ '$VETH1' already in namespace '$DUT_NS'"
else
    ip link set "$VETH1" netns "$DUT_NS"
    echo "  ✓ Moved '$VETH1' to namespace '$DUT_NS'"
fi

echo -e "${YELLOW}4. Configuring IP addresses...${NC}"

# Configure veth0 in gen namespace (idempotent)
if ip netns exec "$GEN_NS" ip addr show "$VETH0" | grep -q "inet $GEN_IP"; then
    echo "  ✓ $GEN_IP already assigned to '$VETH0' in '$GEN_NS'"
else
    ip netns exec "$GEN_NS" ip addr add "$GEN_IP" dev "$VETH0"
    echo "  ✓ Assigned $GEN_IP to '$VETH0' in '$GEN_NS'"
fi

# Configure veth1 in dut namespace (idempotent)
if ip netns exec "$DUT_NS" ip addr show "$VETH1" | grep -q "inet $DUT_IP"; then
    echo "  ✓ $DUT_IP already assigned to '$VETH1' in '$DUT_NS'"
else
    ip netns exec "$DUT_NS" ip addr add "$DUT_IP" dev "$VETH1"
    echo "  ✓ Assigned $DUT_IP to '$VETH1' in '$DUT_NS'"
fi

echo -e "${YELLOW}5. Bringing interfaces up...${NC}"

# Bring up veth0 in gen namespace (idempotent)
if ip netns exec "$GEN_NS" ip link show "$VETH0" | grep -q "state UP"; then
    echo "  ✓ '$VETH0' already up in '$GEN_NS'"
else
    ip netns exec "$GEN_NS" ip link set "$VETH0" up
    echo "  ✓ Brought up '$VETH0' in '$GEN_NS'"
fi

# Bring up veth1 in dut namespace (idempotent)
if ip netns exec "$DUT_NS" ip link show "$VETH1" | grep -q "state UP"; then
    echo "  ✓ '$VETH1' already up in '$DUT_NS'"
else
    ip netns exec "$DUT_NS" ip link set "$VETH1" up
    echo "  ✓ Brought up '$VETH1' in '$DUT_NS'"
fi

echo -e "${GREEN}=== Setup Complete! ===${NC}"
echo ""
echo -e "${BLUE}Testing Instructions:${NC}"
echo ""
echo -e "${YELLOW}Terminal 1 (Generator):${NC}"
echo "  # Generate TCP traffic:"
echo "  ip netns exec $GEN_NS ping -i 0.2 $DUT_IP"
echo ""
echo "  # Generate UDP traffic:"
echo "  ip netns exec $GEN_NS nc -u $DUT_IP 9999"
echo ""
echo -e "${YELLOW}Terminal 2 (Device Under Test):${NC}"
echo "  # Sniff packets:"
echo "  ip netns exec $DUT_NS ./afp sniff3 --in $VETH1"
echo ""
echo "  # Forward packets (mirror mode):"
echo "  ip netns exec $DUT_NS ./afp forward --in $VETH1 --out $VETH1"
echo ""
echo "  # Test with rules:"
echo "  ip netns exec $DUT_NS ./afp sniff3 --in $VETH1 --rule 'proto=TCP,action=DROP'"
echo "  ip netns exec $DUT_NS ./afp forward --in $VETH1 --out $VETH1 --rule 'proto=UDP,dport=9999,action=FORWARD'"
echo ""
echo -e "${BLUE}Network Topology:${NC}"
echo "  gen namespace (10.0.0.1) ←→ veth0 ←→ veth1 ←→ dut namespace (10.0.0.2)"
echo ""
echo -e "${YELLOW}To cleanup:${NC}"
echo "  sudo ./scripts/netns-down.sh"
echo ""
