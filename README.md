# AFP - Simple Route

A C++ project that recreates a router-like behaviour for a linux server.

## Prerequisites

- **Operating System**: Linux
- **Compiler**: GCC or Clang with C++17 support
- **Build System**: CMake 3.10 or later
- **Permissions**: Either `sudo` access or capability to set network capabilities

## Building

### Using Makefile (Recommended)

```bash
# Build the project
make

# Build and run with usage information
make run

# Clean build artifacts
make clean

# Install (requires sudo)
make install
```

### Using CMake directly

```bash
# Create build directory
mkdir build && cd build

# Configure and build
cmake ..
make

# Run with usage information
make run

# Install (requires sudo)
make install
```

## Running

After building, you can run the executable:

```bash
# Run with usage information
./afp --help

# For network operations, you may need elevated privileges:
sudo ./afp [options]

# Or set capabilities (alternative to sudo):
sudo setcap cap_net_raw,cap_net_admin+ep ./afp
./afp [options]
```

## Project Structure

```
simpleroute/
├── CMakeLists.txt     # Main CMake configuration
├── Makefile           # Wrapper for CMake
├── README.md          # This file
├── .clang-format      # Code formatting configuration
├── .gitignore         # Git ignore patterns
├── src/               # Source files (.cpp, .c)
├── include/           # Header files (.hpp, .h)
├── scripts/           # Build and utility scripts
└── docs/              # Documentation
```

## Development

The project uses:
- **C++17** standard
- **Compiler flags**: `-Wall -Wextra -Wpedantic -O2`
- **Code style**: LLVM style with 100-column limit (see `.clang-format`)

## Capabilities

This application may require network capabilities for raw socket operations:
- `cap_net_raw`: For raw socket access
- `cap_net_admin`: For network administration operations

Set these capabilities using:
```bash
sudo setcap cap_net_raw,cap_net_admin+ep ./afp
```

The goal of this thesis is to implement a simple packet processing application in user space 
using Linux raw sockets (AF_PACKET). The application will capture packets starting from the 
Ethernet header, parse higher-layer headers (IPv4/IPv6, TCP/UDP), and apply basic actions such 
as filtering or forwarding. The work demonstrates how AF_PACKET sockets can be used to build a 
minimal user-space network function without relying on specialized frameworks like DPDK.
