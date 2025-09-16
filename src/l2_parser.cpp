#include "l2_parser.h"
#include <sstream>
#include <iomanip>
#include <cstring>
#include <arpa/inet.h>

L2Info L2Parser::parse(const std::vector<uint8_t>& packet_data, size_t start_offset) {
    L2Info result = {};
    
    if (packet_data.size() < start_offset + 14) {
        result.parsed = false;
        return result;
    }

    const uint8_t* data = packet_data.data() + start_offset;
    
    // Extract MAC addresses
    uint8_t dst_mac[6], src_mac[6];
    memcpy(dst_mac, data, 6);
    memcpy(src_mac, data + 6, 6);
    
    result.src_mac = mac_to_string(src_mac);
    result.dst_mac = mac_to_string(dst_mac);
    
    // Extract EtherType
    uint16_t ether_type = ntohs(*(uint16_t*)(data + 12));
    result.ether_type = ether_type;
    result.protocol_name = get_protocol_name(ether_type);
    
    // Handle VLAN tag if present
    if (ether_type == 0x8100 && packet_data.size() >= start_offset + 18) {
        result.has_vlan = true;
        uint16_t vlan_tci = ntohs(*(uint16_t*)(data + 14));
        uint16_t inner_type = ntohs(*(uint16_t*)(data + 16));
        
        result.vlan_id = vlan_tci & 0x0FFF;
        result.vlan_priority = (vlan_tci >> 13) & 0x07;
        result.inner_ether_type = inner_type;
        result.header_length = 18;
        result.next_layer_offset = start_offset + 18;
        
        // Update protocol name to inner type
        result.protocol_name = get_protocol_name(inner_type);
    } else {
        result.has_vlan = false;
        result.vlan_id = 0;
        result.vlan_priority = 0;
        result.inner_ether_type = ether_type;
        result.header_length = 14;
        result.next_layer_offset = start_offset + 14;
    }
    
    // Create string representation
    std::ostringstream oss;
    oss << "ETH " << result.src_mac << " -> " << result.dst_mac 
        << " [" << result.protocol_name << "]";
    
    if (result.has_vlan) {
        oss << " VLAN:" << result.vlan_id;
    }
    
    result.info_string = oss.str();
    result.parsed = true;
    
    return result;
}

std::string L2Parser::mac_to_string(const uint8_t mac[6]) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        if (i > 0) oss << ":";
        oss << std::setw(2) << static_cast<unsigned>(mac[i]);
    }
    return oss.str();
}

std::string L2Parser::get_protocol_name(uint16_t ether_type) {
    switch (ether_type) {
        case 0x0800: return "IPv4";
        case 0x86DD: return "IPv6";
        case 0x0806: return "ARP";
        case 0x8100: return "VLAN";
        case 0x88A8: return "QinQ";
        case 0x8847: return "MPLS";
        default: return "0x" + std::to_string(ether_type);
    }
}
