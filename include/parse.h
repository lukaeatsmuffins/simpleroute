#pragma once

#include <stdint.h>

/**
 * Safe packet parser for network protocols
 * 
 * This module provides safe parsing of network packets starting from Ethernet
 * headers and walking up the protocol stack to identify and extract key fields.
 */

// Ethernet header (14 bytes)
struct Eth {
    uint8_t dst[6];  // Destination MAC address
    uint8_t src[6];  // Source MAC address
    uint16_t type;   // EtherType (network byte order)
};

// VLAN tag (4 bytes)
struct Vlan {
    uint16_t tci;    // Tag Control Information (network byte order)
    uint16_t type;   // EtherType after VLAN (network byte order)
};

// IPv4 header (20 bytes minimum)
struct Ipv4 {
    uint8_t version_ihl;  // Version (4 bits) + IHL (4 bits)
    uint8_t tos;          // Type of Service
    uint16_t total_len;   // Total length (network byte order)
    uint16_t id;          // Identification (network byte order)
    uint16_t frag_off;    // Fragment offset + flags (network byte order)
    uint8_t ttl;          // Time to Live
    uint8_t protocol;     // Protocol
    uint16_t checksum;   // Header checksum (network byte order)
    uint32_t src;         // Source IP address (network byte order)
    uint32_t dst;         // Destination IP address (network byte order)
};

// IPv6 header (40 bytes)
struct Ipv6 {
    uint32_t version_tc_fl;  // Version (4 bits) + Traffic Class (8 bits) + Flow Label (20 bits)
    uint16_t payload_len;    // Payload length (network byte order)
    uint8_t next_header;     // Next header (protocol)
    uint8_t hop_limit;       // Hop limit
    uint8_t src[16];         // Source IPv6 address
    uint8_t dst[16];         // Destination IPv6 address
};

// UDP header (8 bytes)
struct Udp {
    uint16_t src_port;  // Source port (network byte order)
    uint16_t dst_port;  // Destination port (network byte order)
    uint16_t len;       // UDP length (network byte order)
    uint16_t checksum;  // UDP checksum (network byte order)
};

// TCP header (20 bytes minimum)
struct Tcp {
    uint16_t src_port;  // Source port (network byte order)
    uint16_t dst_port;  // Destination port (network byte order)
    uint32_t seq;       // Sequence number (network byte order)
    uint32_t ack;       // Acknowledgment number (network byte order)
    uint8_t data_off;  // Data offset (4 bits) + reserved (4 bits)
    uint8_t flags;      // TCP flags
    uint16_t window;   // Window size (network byte order)
    uint16_t checksum; // TCP checksum (network byte order)
    uint16_t urg_ptr;   // Urgent pointer (network byte order)
};

// Aggregate structure for parsed packet
struct Parsed {
    // Layer flags
    bool has_eth;
    bool has_vlan;
    bool has_ipv4;
    bool has_ipv6;
    bool has_udp;
    bool has_tcp;
    
    // Parsed headers
    Eth eth;
    Vlan vlan;
    Ipv4 ipv4;
    Ipv6 ipv6;
    Udp udp;
    Tcp tcp;
    
    // Additional info
    uint32_t total_len;  // Total packet length
    uint32_t payload_len; // Payload length after all headers
};

/**
 * Parse a network frame starting from Ethernet header
 * @param buf Buffer containing the packet data
 * @param len Length of the packet data
 * @param out Output structure to fill with parsed data
 * @return 0 on success, negative on error
 */
int parse_frame(const uint8_t* buf, uint32_t len, Parsed* out);

/**
 * Pretty print a parsed packet in a single line
 * @param parsed Pointer to parsed packet structure
 */
void parsed_print(const Parsed* parsed);
