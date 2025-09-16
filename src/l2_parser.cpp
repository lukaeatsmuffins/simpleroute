#include "l2_parser.h"
#include <sstream>
#include <iomanip>
#include <arpa/inet.h>

std::string L2Parser::parse(const std::vector<uint8_t>& packet_data, size_t start_offset) {
    if (packet_data.size() < start_offset + 14) {
        return "";
    }

    const uint8_t* data = packet_data.data() + start_offset;
    
    // Extract MAC addresses
    uint8_t dst_mac[6], src_mac[6];
    std::memcpy(dst_mac, data, 6);
    std::memcpy(src_mac, data + 6, 6);
    
    // Extract EtherType
    uint16_t ether_type = ntohs(*(uint16_t*)(data + 12));
    
    std::ostringstream oss;
    oss << "ETH " << mac_to_string(src_mac) << " -> " << mac_to_string(dst_mac) 
        << " [" << get_protocol_name(ether_type) << "]";
    
    // Handle VLAN tag if present
    if (ether_type == 0x8100 && packet_data.size() >= start_offset + 18) {
        uint16_t vlan_tci = ntohs(*(uint16_t*)(data + 14));
        uint16_t inner_type = ntohs(*(uint16_t*)(data + 16));
        uint16_t vlan_id = vlan_tci & 0x0FFF;
        
        oss << " VLAN:" << vlan_id << " [" << get_protocol_name(inner_type) << "]";
    }
    
    return oss.str();
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
