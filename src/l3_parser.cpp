#include "l3_parser.h"
#include <sstream>
#include <iomanip>
#include <arpa/inet.h>

std::string L3Parser::parse(const std::vector<uint8_t>& packet_data, size_t start_offset) {
    if (packet_data.size() < start_offset + 1) {
        return "";
    }

    uint8_t version = (packet_data[start_offset] >> 4) & 0x0F;
    
    if (version == 4) {
        return parse_ipv4(packet_data, start_offset);
    } else if (version == 6) {
        return parse_ipv6(packet_data, start_offset);
    }
    
    return "";
}

std::string L3Parser::parse_ipv4(const std::vector<uint8_t>& packet_data, size_t start_offset) {
    if (packet_data.size() < start_offset + 20) {
        return "";
    }

    const uint8_t* data = packet_data.data() + start_offset;
    
    uint8_t ihl = data[0] & 0x0F;
    uint8_t protocol = data[9];
    uint32_t src_addr = *(uint32_t*)(data + 12);
    uint32_t dst_addr = *(uint32_t*)(data + 16);
    uint16_t frag_off = ntohs(*(uint16_t*)(data + 6));
    
    std::ostringstream oss;
    oss << "IPv4 " << ipv4_to_string(src_addr) << " -> " << ipv4_to_string(dst_addr)
        << " [" << get_protocol_name(protocol) << "]";
    
    if (is_ipv4_fragmented(frag_off)) {
        oss << " FRAG";
    }
    
    if (ihl > 5) {
        oss << " +opts";
    }
    
    return oss.str();
}

std::string L3Parser::parse_ipv6(const std::vector<uint8_t>& packet_data, size_t start_offset) {
    if (packet_data.size() < start_offset + 40) {
        return "";
    }

    const uint8_t* data = packet_data.data() + start_offset;
    
    uint8_t next_header = data[6];
    const uint8_t* src_addr = data + 8;
    const uint8_t* dst_addr = data + 24;
    
    std::ostringstream oss;
    oss << "IPv6 " << ipv6_to_string(src_addr) << " -> " << ipv6_to_string(dst_addr)
        << " [" << get_protocol_name(next_header) << "]";
    
    return oss.str();
}

std::string L3Parser::ipv4_to_string(const uint32_t addr) {
    struct in_addr in_addr;
    in_addr.s_addr = addr;
    return std::string(inet_ntoa(in_addr));
}

std::string L3Parser::ipv6_to_string(const uint8_t addr[16]) {
    char str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, addr, str, INET6_ADDRSTRLEN);
    return std::string(str);
}

std::string L3Parser::get_protocol_name(const uint8_t protocol) {
    switch (protocol) {
        case 1: return "ICMP";
        case 6: return "TCP";
        case 17: return "UDP";
        case 41: return "IPv6";
        case 58: return "ICMPv6";
        case 89: return "OSPF";
        case 132: return "SCTP";
        default: return std::to_string(protocol);
    }
}

bool L3Parser::is_ipv4_fragmented(const uint16_t frag_off) {
    return (frag_off & 0x3FFF) != 0 || (frag_off & 0x2000) != 0;
}
