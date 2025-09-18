#pragma once

#include <string>
#include <vector>
#include <stdint.h>

// Layer 2 (Ethernet) information structure.
struct L2Info {
    // Parsing success.
    bool parsed;                    // Whether parsing was successful
    
    // MAC addresses.
    std::string src_mac;            // Source MAC address (XX:XX:XX:XX:XX:XX)
    std::string dst_mac;            // Destination MAC address
    
    // Protocol information.
    uint16_t ether_type;            // EtherType field
    std::string protocol_name;      // Protocol name (IPv4, IPv6, ARP, etc.)
    
    // VLAN information.
    bool has_vlan;                  // VLAN tag present
    uint16_t vlan_id;               // VLAN ID (if has_vlan is true)
    uint8_t vlan_priority;          // VLAN priority
    uint16_t inner_ether_type;      // EtherType after VLAN tag
    
    // Header information.
    uint32_t header_length;         // L2 header length in bytes
    uint32_t next_layer_offset;     // Offset to next layer header
    
    // String representation.
    std::string info_string;        // Formatted string representation
};

// Layer 2 (Ethernet) Parser - Stateless parser for Ethernet frames and VLAN tags.
class L2Parser {
public:
    // Parse Ethernet frame and return detailed information.
    static L2Info parse(const std::vector<uint8_t>& packet_data, size_t start_offset = 0);
    
    // Serialize L2 information to capture format.
    static std::string serialize(const L2Info& l2_info);

    // Deserialize L2 information from capture format.
    static L2Info deserialize(const std::string& layer_string);

private:
    // Convert MAC address to string.
    static std::string mac_to_string(const uint8_t mac[6]);

    // Get protocol name from EtherType.
    static std::string get_protocol_name(uint16_t ether_type);
};
