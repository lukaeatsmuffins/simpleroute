#!/bin/bash

# DPDK Setup Script for Linux
# This script installs and configures DPDK for use in projects
#
# Usage:
#   For VM environments:    sudo ./setup_dpdk.sh --env vm
#   For physical machines:  sudo ./setup_dpdk.sh --env physical
#
# Options:
#   --env <type>    : Environment type (required)
#                     - "vm"       : VM mode (uses virtual PMD drivers)
#                     - "physical" : Physical machine mode (uses physical NICs)
#   --help, -h      : Show this help message

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration variables
DPDK_VERSION="24.11.3"
DPDK_DIR="/opt/dpdk"
INSTALL_PREFIX="/usr/local"
HUGE_PAGES_SIZE="2048"
HUGE_PAGES_NUM="1024"

# Environment type: "vm" for virtual machines, "physical" for physical machines
ENVIRONMENT_TYPE=""

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to show help
show_help() {
    echo "DPDK Setup Script for Linux"
    echo ""
    echo "Usage:"
    echo "  sudo ./setup_dpdk.sh --env <type>"
    echo ""
    echo "Options:"
    echo "  --env <type>    Environment type (required)"
    echo "                  - vm       : VM mode (uses virtual PMD drivers)"
    echo "                  - physical : Physical machine mode (uses physical NICs)"
    echo "  --help, -h      Show this help message"
    echo ""
    echo "Examples:"
    echo "  sudo ./setup_dpdk.sh --env vm"
    echo "  sudo ./setup_dpdk.sh --env physical"
}

# Function to parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --env)
                ENVIRONMENT_TYPE="$2"
                shift 2
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                echo ""
                show_help
                exit 1
                ;;
        esac
    done
    
    # Validate environment type
    if [[ -z "$ENVIRONMENT_TYPE" ]]; then
        print_error "Environment type is required!"
        echo ""
        show_help
        exit 1
    fi
    
    if [[ "$ENVIRONMENT_TYPE" != "vm" && "$ENVIRONMENT_TYPE" != "physical" ]]; then
        print_error "Invalid environment type: $ENVIRONMENT_TYPE"
        print_error "Valid values: 'vm' or 'physical'"
        echo ""
        show_help
        exit 1
    fi
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Function to detect OS and package manager
detect_os() {
    if command -v apt-get &> /dev/null; then
        PKG_MANAGER="apt"
        UPDATE_CMD="apt-get update"
        INSTALL_CMD="apt-get install -y"
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
        UPDATE_CMD="yum update -y"
        INSTALL_CMD="yum install -y"
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
        UPDATE_CMD="dnf update -y"
        INSTALL_CMD="dnf install -y"
    else
        print_error "Unsupported package manager. Please install dependencies manually."
        exit 1
    fi
    print_status "Detected package manager: $PKG_MANAGER"
}

# Function to install dependencies
install_dependencies() {
    print_status "Installing DPDK dependencies..."
    
    # Update package list
    $UPDATE_CMD
    
    # Install build tools and dependencies
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        $INSTALL_CMD build-essential meson ninja-build python3-pip python3-setuptools \
                   libnuma-dev pkg-config libpcap-dev libssl-dev \
                   libelf-dev libjansson-dev liblua5.3-dev \
                   linux-headers-$(uname -r) git wget pciutils
    elif [[ "$PKG_MANAGER" == "yum" || "$PKG_MANAGER" == "dnf" ]]; then
        $INSTALL_CMD gcc gcc-c++ make meson ninja-build python3-pip \
                   numactl-devel pkgconfig libpcap-devel openssl-devel \
                   elfutils-libelf-devel jansson-devel lua-devel \
                   kernel-devel git wget pciutils
    fi
    
    # Install Python packages
    pip3 install --upgrade pip
    pip3 install meson ninja pyelftools
    
    print_success "Dependencies installed successfully"
}

# Function to setup hugepages
setup_hugepages() {
    print_status "Setting up hugepages..."
    
    # Create hugepages directory
    mkdir -p /dev/hugepages
    
    # Mount hugepages if not already mounted
    if ! mountpoint -q /dev/hugepages; then
        mount -t hugetlbfs nodev /dev/hugepages
        print_status "Mounted hugepages filesystem"
    else
        print_status "Hugepages filesystem already mounted"
    fi
    
    # Configure hugepages in sysctl
    echo "vm.nr_hugepages=$HUGE_PAGES_NUM" > /etc/sysctl.d/99-hugepages.conf
    echo "vm.hugetlb_shm_group=0" >> /etc/sysctl.d/99-hugepages.conf
    
    # Apply hugepages configuration
    sysctl -w vm.nr_hugepages=$HUGE_PAGES_NUM
    
    # Verify hugepages setup
    HUGE_PAGES_AVAILABLE=$(grep HugePages_Free /proc/meminfo | awk '{print $2}')
    if [[ $HUGE_PAGES_AVAILABLE -gt 0 ]]; then
        print_success "Hugepages configured: $HUGE_PAGES_AVAILABLE pages available"
    else
        print_warning "No hugepages available. You may need to reboot."
    fi
}

# Function to download and build DPDK
build_dpdk() {
    print_status "Downloading and building DPDK $DPDK_VERSION..."
    
    # Create DPDK directory
    mkdir -p $DPDK_DIR
    cd $DPDK_DIR
    
    # Download DPDK if not already present
    if [[ ! -f "dpdk-$DPDK_VERSION.tar.xz" ]]; then
        print_status "Downloading DPDK $DPDK_VERSION..."
        wget -O dpdk-$DPDK_VERSION.tar.xz "https://fast.dpdk.org/rel/dpdk-$DPDK_VERSION.tar.xz"
    else
        print_status "DPDK archive already exists, skipping download"
    fi
    
    # Extract DPDK
    if [[ ! -d "dpdk-$DPDK_VERSION" ]]; then
        print_status "Extracting DPDK..."
        tar -xf dpdk-$DPDK_VERSION.tar.xz
    else
        print_status "DPDK source already extracted"
    fi

    cd dpdk-stable-$DPDK_VERSION
    
    # Configure build
    print_status "Configuring DPDK build..."
    meson setup build \
        --prefix=$INSTALL_PREFIX \
        --libdir=lib \
        --buildtype=release \
        -Dexamples=all \
        -Dtests=false
    
    # Build DPDK
    print_status "Building DPDK (this may take several minutes)..."
    cd build
    ninja
    
    # Install DPDK
    print_status "Installing DPDK..."
    ninja install
    
    # Update library cache
    ldconfig
    
    print_success "DPDK built and installed successfully"
}

# Function to setup environment
setup_environment() {
    print_status "Setting up DPDK environment..."
    
    # Create environment script
    cat > /etc/profile.d/dpdk.sh << EOF
# DPDK Environment Variables
export RTE_SDK=$DPDK_DIR/dpdk-$DPDK_VERSION
export RTE_TARGET=x86_64-native-linux-gcc
export PKG_CONFIG_PATH=$INSTALL_PREFIX/lib/pkgconfig:\$PKG_CONFIG_PATH
export LD_LIBRARY_PATH=$INSTALL_PREFIX/lib:\$LD_LIBRARY_PATH
EOF
    
    # Source environment for current session
    source /etc/profile.d/dpdk.sh
    
    print_success "DPDK environment configured"
}

# Function to load required kernel modules
load_kernel_modules() {
    print_status "Loading required kernel modules..."
    
    # Load UIO modules
    modprobe uio
    modprobe uio_pci_generic
    
    # Make modules persistent
    echo "uio" >> /etc/modules
    echo "uio_pci_generic" >> /etc/modules
    
    print_success "Kernel modules loaded"
}


# Function to show network interfaces
show_interfaces() {
    print_status "Available network interfaces:"
    echo
    lspci | grep -i ethernet
    echo
    
    if [[ "$ENVIRONMENT_TYPE" == "vm" ]]; then
        print_warning "VM Environment Mode!"
        print_status "In VM environments, you typically cannot bind physical NICs to DPDK."
        print_status "For VM testing, use DPDK's virtual PMD drivers."
        print_status "See the example script: dpdk_example.sh"
        echo
        print_status "VM-compatible DPDK commands:"
        print_status "dpdk-testpmd -l 0-1 -n 4 --huge-dir=/dev/hugepages --vdev=net_null0 --vdev=net_null1 -- -i"
    else
        print_status "Physical Machine Mode!"
        print_status "To bind interfaces to DPDK, use:"
        print_status "dpdk-devbind.py --bind=uio_pci_generic <PCI_ADDRESS>"
        print_status "Example: dpdk-devbind.py --bind=uio_pci_generic 0000:01:00.0"
    fi
}

# Function to create example script
create_example_script() {
    print_status "Creating example DPDK application script..."
    
    # Check environment type
    if [[ "$ENVIRONMENT_TYPE" == "vm" ]]; then
        print_status "VM environment mode - creating VM-compatible example..."
        
        cat > /root/dipl/simpleroute/dpdk_example.sh << 'EOF'
#!/bin/bash

# Example DPDK Application Script for VM Environments
# This script demonstrates how to run DPDK applications in VMs using virtual PMD drivers

# Source DPDK environment
source /etc/profile.d/dpdk.sh

# Set up hugepages (if not already done)
echo 1024 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages

echo "Running DPDK VM example..."
echo "This example uses virtual PMD drivers suitable for VM environments"
echo "Press Ctrl+C to exit"
echo

# Example 1: NULL PMD (CPU-only test, no network required)
echo "=== Example 1: NULL PMD Test (Recommended for VMs) ==="
dpdk-testpmd -l 0-1 -n 4 --huge-dir=/dev/hugepages \
        --file-prefix=testpmd-null \
        --vdev=net_null0 \
        --vdev=net_null1 \
        -- -i --portmask=0x3 \
        --nb-cores=1 --nb-ports=2 \
        --total-num-mbufs=2048

# Uncomment the following examples if you want to try other PMD drivers:

# Example 2: PCAP PMD (uses loopback interface)
# echo "=== Example 2: PCAP PMD Test ==="
# dpdk-testpmd -l 0-1 -n 4 --huge-dir=/dev/hugepages \
#         --file-prefix=testpmd-pcap \
#         --vdev=net_pcap0,iface=lo \
#         --vdev=net_pcap1,iface=lo \
#         -- -i --portmask=0x3 \
#         --nb-cores=1 --nb-ports=2 \
#         --total-num-mbufs=2048

# Example 3: TAP PMD (creates virtual network interfaces)
# echo "=== Example 3: TAP PMD Test ==="
# dpdk-testpmd -l 0-1 -n 4 --huge-dir=/dev/hugepages \
#         --file-prefix=testpmd-tap \
#         --vdev=net_tap0 \
#         --vdev=net_tap1 \
#         -- -i --portmask=0x3 \
#         --nb-cores=1 --nb-ports=2 \
#         --total-num-mbufs=2048
EOF
    else
        print_status "Physical machine detected - creating standard example..."
        
        cat > /root/dipl/simpleroute/dpdk_example.sh << 'EOF'
#!/bin/bash

# Example DPDK Application Script for Physical Machines
# This script demonstrates how to run a simple DPDK application

# Source DPDK environment
source /etc/profile.d/dpdk.sh

# Set up hugepages (if not already done)
echo 1024 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages

# Run DPDK testpmd application
# This is a simple packet generator/analyzer
echo "Running DPDK testpmd application..."
echo "Press Ctrl+C to exit"
echo

# Basic testpmd command (adjust parameters as needed)
dpdk-testpmd -l 0-1 -n 4 --huge-dir=/dev/hugepages \
        --file-prefix=testpmd \
        -- -i --portmask=0x1 \
        --nb-cores=1 --nb-ports=1 \
        --total-num-mbufs=2048
EOF
    fi
    
    chmod +x /root/dipl/simpleroute/dpdk_example.sh
    print_success "Example script created: dpdk_example.sh"
}

# Function to validate installation
validate_installation() {
    print_status "Validating DPDK installation..."
    
    # Check if DPDK tools are available
    if command -v dpdk-testpmd &> /dev/null; then
        print_success "DPDK tools are available"
    else
        print_error "DPDK tools not found in PATH"
        return 1
    fi
    
    # Check hugepages
    HUGE_PAGES_AVAILABLE=$(grep HugePages_Free /proc/meminfo | awk '{print $2}')
    if [[ $HUGE_PAGES_AVAILABLE -gt 0 ]]; then
        print_success "Hugepages available: $HUGE_PAGES_AVAILABLE"
    else
        print_warning "No hugepages available"
    fi
    
    # Check kernel modules
    if lsmod | grep -q uio; then
        print_success "UIO modules loaded"
    else
        print_warning "UIO modules not loaded"
    fi
    
    print_success "DPDK installation validation completed"
}

# Main execution
main() {
    print_status "Starting DPDK setup..."
    print_status "DPDK Version: $DPDK_VERSION"
    print_status "Install Directory: $DPDK_DIR"
    print_status "Install Prefix: $INSTALL_PREFIX"
    print_status "Environment Type: $ENVIRONMENT_TYPE"
    echo
    
    check_root
    detect_os
    # install_dependencies
    # setup_hugepages
    # build_dpdk
    # setup_environment
    # load_kernel_modules
    create_example_script
    validate_installation
    
    echo
    print_success "DPDK setup completed successfully!"
    echo
    
    if [[ "$ENVIRONMENT_TYPE" == "vm" ]]; then
        print_status "VM Environment Mode - Next steps:"
        print_status "1. Reboot your system to ensure all changes take effect"
        print_status "2. Run the VM-compatible example script: ./dpdk_example.sh"
        print_status "3. The example uses virtual PMD drivers (no physical NIC binding required)"
        print_status "4. For testing, use: dpdk-testpmd -l 0-1 -n 4 --huge-dir=/dev/hugepages --vdev=net_null0 --vdev=net_null1 -- -i"
    else
        print_status "Physical Machine Mode - Next steps:"
        print_status "1. Reboot your system to ensure all changes take effect"
        print_status "2. Use 'dpdk-devbind.py --status' to see available interfaces"
        print_status "3. Bind network interfaces with 'dpdk-devbind.py --bind=uio_pci_generic <PCI_ADDRESS>'"
        print_status "4. Run the example script: ./dpdk_example.sh"
    fi
    echo
    show_interfaces
}

# Parse command line arguments first
parse_arguments "$@"

# Run main function
main
