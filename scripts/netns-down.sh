#!/bin/bash

# Network namespace cleanup script for AFP testing
# Safely removes namespaces and veth pairs

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

echo -e "${BLUE}=== AFP Network Namespace Cleanup ===${NC}"
echo "Cleaning up testing environment..."

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

# Function to check if veth exists
veth_exists() {
    ip link show "$1" >/dev/null 2>&1
}

echo -e "${YELLOW}1. Checking for active processes in namespaces...${NC}"

# Check for running processes in gen namespace
if ns_exists "$GEN_NS"; then
    GEN_PROCESSES=$(ip netns exec "$GEN_NS" ps aux 2>/dev/null | wc -l)
    if [ "$GEN_PROCESSES" -gt 1 ]; then
        echo "  ⚠ Found $((GEN_PROCESSES-1)) processes in '$GEN_NS' namespace"
        echo "  Consider stopping them before cleanup"
    else
        echo "  ✓ No active processes in '$GEN_NS' namespace"
    fi
fi

# Check for running processes in dut namespace
if ns_exists "$DUT_NS"; then
    DUT_PROCESSES=$(ip netns exec "$DUT_NS" ps aux 2>/dev/null | wc -l)
    if [ "$DUT_PROCESSES" -gt 1 ]; then
        echo "  ⚠ Found $((DUT_PROCESSES-1)) processes in '$DUT_NS' namespace"
        echo "  Consider stopping them before cleanup"
    else
        echo "  ✓ No active processes in '$DUT_NS' namespace"
    fi
fi

echo -e "${YELLOW}2. Removing veth interfaces...${NC}"

# Remove veth interfaces (idempotent)
if veth_exists "$VETH0"; then
    ip link delete "$VETH0" 2>/dev/null || true
    echo "  ✓ Removed '$VETH0'"
else
    echo "  ✓ '$VETH0' not found (already removed)"
fi

if veth_exists "$VETH1"; then
    ip link delete "$VETH1" 2>/dev/null || true
    echo "  ✓ Removed '$VETH1'"
else
    echo "  ✓ '$VETH1' not found (already removed)"
fi

echo -e "${YELLOW}3. Removing network namespaces...${NC}"

# Remove gen namespace (idempotent)
if ns_exists "$GEN_NS"; then
    ip netns delete "$GEN_NS"
    echo "  ✓ Removed namespace '$GEN_NS'"
else
    echo "  ✓ Namespace '$GEN_NS' not found (already removed)"
fi

# Remove dut namespace (idempotent)
if ns_exists "$DUT_NS"; then
    ip netns delete "$DUT_NS"
    echo "  ✓ Removed namespace '$DUT_NS'"
else
    echo "  ✓ Namespace '$DUT_NS' not found (already removed)"
fi

echo -e "${GREEN}=== Cleanup Complete! ===${NC}"
echo ""
echo -e "${BLUE}Verification:${NC}"
echo "Checking remaining namespaces..."

REMAINING_NS=$(ip netns list | grep -E "^($GEN_NS|$DUT_NS) " || true)
if [ -z "$REMAINING_NS" ]; then
    echo -e "${GREEN}✓ All AFP namespaces successfully removed${NC}"
else
    echo -e "${RED}⚠ Warning: Some namespaces still exist:${NC}"
    echo "$REMAINING_NS"
fi

REMAINING_VETH=$(ip link show | grep -E "^[0-9]+: ($VETH0|$VETH1):" || true)
if [ -z "$REMAINING_VETH" ]; then
    echo -e "${GREEN}✓ All AFP veth interfaces successfully removed${NC}"
else
    echo -e "${RED}⚠ Warning: Some veth interfaces still exist:${NC}"
    echo "$REMAINING_VETH"
fi

echo ""
echo -e "${YELLOW}To setup again:${NC}"
echo "  sudo ./scripts/netns-up.sh"
echo ""
