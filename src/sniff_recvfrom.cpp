#include "sniff_recvfrom.h"
#include "parse.h"
#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>

int sniff_packets(const std::string& interface_name) {
    // Create raw socket
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        std::cerr << "Error: Failed to create raw socket. "
                  << "Make sure you have CAP_NET_RAW capability or run with sudo." << std::endl;
        return -1;
    }

    // Get interface index
    int ifindex = if_nametoindex(interface_name.c_str());
    if (ifindex == 0) {
        std::cerr << "Error: Interface '" << interface_name << "' not found." << std::endl;
        close(sockfd);
        return -1;
    }

    // Bind socket to interface
    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = ifindex;

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "Error: Failed to bind to interface '" << interface_name << "'." << std::endl;
        close(sockfd);
        return -1;
    }

    std::cout << "Sniffing packets on interface: " << interface_name << std::endl;
    std::cout << "Press Ctrl+C to stop..." << std::endl;

    // Buffer for receiving packets
    char buffer[2048];
    struct sockaddr_ll src_addr;
    socklen_t addr_len = sizeof(src_addr);

    // Main sniffing loop
    while (true) {
        ssize_t bytes_received = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                                         (struct sockaddr*)&src_addr, &addr_len);
        
        if (bytes_received < 0) {
            std::cerr << "Error: Failed to receive packet." << std::endl;
            continue;
        }

        // Parse and print packet summary
        Parsed parsed;
        int parse_result = parse_frame(reinterpret_cast<const uint8_t*>(buffer), 
                                      static_cast<uint32_t>(bytes_received), &parsed);
        
        if (parse_result == 0) {
            // Successfully parsed - print structured output
            parsed_print(&parsed);
        } else {
            // Parse failed - fall back to hex output
            std::cout << "Length: " << std::setw(4) << bytes_received << " | ";
            std::cout << "Data: ";
            
            // Print first 14 bytes (Ethernet header) in hex
            int bytes_to_print = std::min(static_cast<int>(bytes_received), 14);
            for (int i = 0; i < bytes_to_print; ++i) {
                std::cout << std::hex << std::setfill('0') << std::setw(2) 
                          << (static_cast<unsigned char>(buffer[i]) & 0xFF) << " ";
            }
            std::cout << std::dec << " (parse error: " << parse_result << ")" << std::endl;
        }
    }

    close(sockfd);
    return 0;
}
