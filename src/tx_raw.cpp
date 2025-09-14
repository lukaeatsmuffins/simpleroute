#include "tx_raw.h"
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>

// Global state for transmitter
static int tx_socket = -1;
static int tx_ifindex = -1;

int tx_open(const char* ifname) {
    if (!ifname) {
        std::cerr << "Error: Interface name cannot be null" << std::endl;
        return -1;
    }

    // Create raw socket for transmission
    tx_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (tx_socket < 0) {
        std::cerr << "Error: Failed to create raw socket for transmission. "
                  << "Make sure you have CAP_NET_RAW capability or run with sudo." << std::endl;
        return -1;
    }

    // Get interface index
    tx_ifindex = if_nametoindex(ifname);
    if (tx_ifindex == 0) {
        std::cerr << "Error: Output interface '" << ifname << "' not found." << std::endl;
        close(tx_socket);
        tx_socket = -1;
        return -1;
    }

    std::cout << "Raw transmitter opened on interface: " << ifname 
              << " (index: " << tx_ifindex << ")" << std::endl;

    return 0;
}

int tx_send(const uint8_t* frame, uint32_t len) {
    if (tx_socket < 0) {
        std::cerr << "Error: Transmitter not initialized" << std::endl;
        return -1;
    }

    if (!frame || len == 0) {
        std::cerr << "Error: Invalid frame data" << std::endl;
        return -1;
    }

    // Prepare socket address for transmission
    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = tx_ifindex;
    addr.sll_halen = 6;  // MAC address length

    // Extract destination MAC from frame (first 6 bytes)
    memcpy(addr.sll_addr, frame, 6);

    // Send the frame
    ssize_t bytes_sent = sendto(tx_socket, frame, len, 0, 
                               (struct sockaddr*)&addr, sizeof(addr));
    
    if (bytes_sent < 0) {
        std::cerr << "Error: Failed to send frame: " << strerror(errno) << std::endl;
        return -1;
    }

    if (static_cast<uint32_t>(bytes_sent) != len) {
        std::cerr << "Warning: Partial send - sent " << bytes_sent 
                  << " of " << len << " bytes" << std::endl;
    }

    return static_cast<int>(bytes_sent);
}

void tx_close(void) {
    if (tx_socket >= 0) {
        close(tx_socket);
        tx_socket = -1;
        tx_ifindex = -1;
        std::cout << "Raw transmitter closed" << std::endl;
    }
}
