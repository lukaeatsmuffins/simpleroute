#include "parse.h"
#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <iomanip>

// Ethernet constants
#define ETH_HEADER_LEN 14
#define ETH_TYPE_VLAN 0x8100
#define ETH_TYPE_IPV4 0x0800
#define ETH_TYPE_IPV6 0x86DD

// VLAN constants
#define VLAN_HEADER_LEN 4

// IPv4 constants
#define IPV4_MIN_HEADER_LEN 20
#define IPV4_PROTO_UDP 17
#define IPV4_PROTO_TCP 6

// IPv6 constants
#define IPV6_HEADER_LEN 40
#define IPV6_PROTO_UDP 17
#define IPV6_PROTO_TCP 6

// UDP constants
#define UDP_HEADER_LEN 8

// TCP constants
#define TCP_MIN_HEADER_LEN 20

// Helper function to convert MAC address to string
static void mac_to_string(const uint8_t* mac, char* str) {
    snprintf(str, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Helper function to convert IPv4 address to string
static void ipv4_to_string(uint32_t ip, char* str) {
    struct in_addr addr;
    addr.s_addr = ip;
    strcpy(str, inet_ntoa(addr));
}

// Helper function to convert IPv6 address to string
static void ipv6_to_string(const uint8_t* ip, char* str) {
    char tmp[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, ip, tmp, INET6_ADDRSTRLEN);
    strcpy(str, tmp);
}

int parse_frame(const uint8_t* buf, uint32_t len, Parsed* out) {
    // Initialize output structure
    memset(out, 0, sizeof(Parsed));
    out->total_len = len;
    
    uint32_t offset = 0;
    
    // Parse Ethernet header
    if (len < ETH_HEADER_LEN) {
        return -1;  // Packet too short for Ethernet header
    }
    
    memcpy(out->eth.dst, buf + offset, 6);
    memcpy(out->eth.src, buf + offset + 6, 6);
    out->eth.type = ntohs(*(uint16_t*)(buf + offset + 12));
    out->has_eth = true;
    offset += ETH_HEADER_LEN;
    
    // Check for VLAN tag
    if (out->eth.type == ETH_TYPE_VLAN) {
        if (len < offset + VLAN_HEADER_LEN) {
            return -2;  // Packet too short for VLAN header
        }
        
        out->vlan.tci = ntohs(*(uint16_t*)(buf + offset));
        out->vlan.type = ntohs(*(uint16_t*)(buf + offset + 2));
        out->has_vlan = true;
        offset += VLAN_HEADER_LEN;
        
        // Use VLAN EtherType for next layer
        out->eth.type = out->vlan.type;
    }
    
    // Parse IP layer
    if (out->eth.type == ETH_TYPE_IPV4) {
        if (len < offset + IPV4_MIN_HEADER_LEN) {
            return -3;  // Packet too short for IPv4 header
        }
        
        memcpy(&out->ipv4, buf + offset, IPV4_MIN_HEADER_LEN);
        out->has_ipv4 = true;
        
        // Calculate IPv4 header length
        uint8_t ihl = out->ipv4.version_ihl & 0x0F;
        uint32_t ipv4_header_len = ihl * 4;
        if (ipv4_header_len < IPV4_MIN_HEADER_LEN || ipv4_header_len > 60) {
            return -4;  // Invalid IPv4 header length
        }
        
        if (len < offset + ipv4_header_len) {
            return -5;  // Packet too short for IPv4 header
        }
        
        offset += ipv4_header_len;
        
        // Parse transport layer
        if (out->ipv4.protocol == IPV4_PROTO_UDP) {
            if (len < offset + UDP_HEADER_LEN) {
                return -6;  // Packet too short for UDP header
            }
            
            memcpy(&out->udp, buf + offset, UDP_HEADER_LEN);
            out->has_udp = true;
            offset += UDP_HEADER_LEN;
            
        } else if (out->ipv4.protocol == IPV4_PROTO_TCP) {
            if (len < offset + TCP_MIN_HEADER_LEN) {
                return -7;  // Packet too short for TCP header
            }
            
            memcpy(&out->tcp, buf + offset, TCP_MIN_HEADER_LEN);
            out->has_tcp = true;
            
            // Calculate TCP header length
            uint8_t tcp_data_off = (out->tcp.data_off >> 4) & 0x0F;
            uint32_t tcp_header_len = tcp_data_off * 4;
            if (tcp_header_len < TCP_MIN_HEADER_LEN || tcp_header_len > 60) {
                return -8;  // Invalid TCP header length
            }
            
            if (len < offset + tcp_header_len) {
                return -9;  // Packet too short for TCP header
            }
            
            offset += tcp_header_len;
        }
        
    } else if (out->eth.type == ETH_TYPE_IPV6) {
        if (len < offset + IPV6_HEADER_LEN) {
            return -10;  // Packet too short for IPv6 header
        }
        
        memcpy(&out->ipv6, buf + offset, IPV6_HEADER_LEN);
        out->has_ipv6 = true;
        offset += IPV6_HEADER_LEN;
        
        // Parse transport layer
        if (out->ipv6.next_header == IPV6_PROTO_UDP) {
            if (len < offset + UDP_HEADER_LEN) {
                return -11;  // Packet too short for UDP header
            }
            
            memcpy(&out->udp, buf + offset, UDP_HEADER_LEN);
            out->has_udp = true;
            offset += UDP_HEADER_LEN;
            
        } else if (out->ipv6.next_header == IPV6_PROTO_TCP) {
            if (len < offset + TCP_MIN_HEADER_LEN) {
                return -12;  // Packet too short for TCP header
            }
            
            memcpy(&out->tcp, buf + offset, TCP_MIN_HEADER_LEN);
            out->has_tcp = true;
            
            // Calculate TCP header length
            uint8_t tcp_data_off = (out->tcp.data_off >> 4) & 0x0F;
            uint32_t tcp_header_len = tcp_data_off * 4;
            if (tcp_header_len < TCP_MIN_HEADER_LEN || tcp_header_len > 60) {
                return -13;  // Invalid TCP header length
            }
            
            if (len < offset + tcp_header_len) {
                return -14;  // Packet too short for TCP header
            }
            
            offset += tcp_header_len;
        }
    }
    
    // Calculate payload length
    out->payload_len = len - offset;
    
    return 0;  // Success
}

void parsed_print(const Parsed* parsed) {
    if (!parsed->has_eth) {
        std::cout << "Invalid packet (no Ethernet header)" << std::endl;
        return;
    }
    
    // Print Ethernet header
    char src_mac[18], dst_mac[18];
    mac_to_string(parsed->eth.src, src_mac);
    mac_to_string(parsed->eth.dst, dst_mac);
    
    std::cout << "ETH src=" << src_mac << " dst=" << dst_mac;
    
    // Print VLAN if present
    if (parsed->has_vlan) {
        uint16_t vlan_id = parsed->vlan.tci & 0x0FFF;
        std::cout << " | VLAN " << vlan_id;
    }
    
    // Print IP layer
    if (parsed->has_ipv4) {
        char src_ip[16], dst_ip[16];
        ipv4_to_string(parsed->ipv4.src, src_ip);
        ipv4_to_string(parsed->ipv4.dst, dst_ip);
        
        std::cout << " | IPv4 " << src_ip << "→" << dst_ip;
        
        // Print protocol
        if (parsed->has_udp) {
            std::cout << " proto=UDP";
        } else if (parsed->has_tcp) {
            std::cout << " proto=TCP";
        } else {
            std::cout << " proto=" << static_cast<int>(parsed->ipv4.protocol);
        }
        
    } else if (parsed->has_ipv6) {
        char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
        ipv6_to_string(parsed->ipv6.src, src_ip);
        ipv6_to_string(parsed->ipv6.dst, dst_ip);
        
        std::cout << " | IPv6 " << src_ip << "→" << dst_ip;
        
        // Print protocol
        if (parsed->has_udp) {
            std::cout << " proto=UDP";
        } else if (parsed->has_tcp) {
            std::cout << " proto=TCP";
        } else {
            std::cout << " proto=" << static_cast<int>(parsed->ipv6.next_header);
        }
    }
    
    // Print transport layer
    if (parsed->has_udp) {
        std::cout << " | UDP " << ntohs(parsed->udp.src_port) 
                  << "→" << ntohs(parsed->udp.dst_port) 
                  << " len=" << parsed->payload_len;
    } else if (parsed->has_tcp) {
        std::cout << " | TCP " << ntohs(parsed->tcp.src_port) 
                  << "→" << ntohs(parsed->tcp.dst_port) 
                  << " len=" << parsed->payload_len;
    }
    
    std::cout << std::endl;
}
