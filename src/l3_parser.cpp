#include "l3_parser.h"
#include <sstream>
#include <iomanip>
#include <arpa/inet.h>

L3Info L3Parser::parse(const std::vector<uint8_t>& packet_data, size_t start_offset) {
    L3Info result = {};
    
    if (packet_data.size() < start_offset + 1) {
        result.parsed = false;
        return result;
    }

    uint8_t version = (packet_data[start_offset] >> 4) & 0x0F;
    result.ip_version = version;
    
    if (version == 4) {
        return parse_ipv4(packet_data, start_offset);
    } else if (version == 6) {
        return parse_ipv6(packet_data, start_offset);
    }
    
    result.parsed = false;
    return result;
}

L3Info L3Parser::parse_ipv4(const std::vector<uint8_t>& packet_data, size_t start_offset) {
    L3Info result = {};
    
    if (packet_data.size() < start_offset + 20) {
        result.parsed = false;
        return result;
    }

    const uint8_t* data = packet_data.data() + start_offset;
    
    uint8_t ihl = data[0] & 0x0F;
    uint8_t protocol = data[9];
    uint32_t src_addr = *(uint32_t*)(data + 12);
    uint32_t dst_addr = *(uint32_t*)(data + 16);
    uint16_t frag_off = ntohs(*(uint16_t*)(data + 6));
    
    // Fill IPv4 specific fields
    result.ip_version = 4;
    result.src_ip = ipv4_to_string(src_addr);
    result.dst_ip = ipv4_to_string(dst_addr);
    result.next_protocol = protocol;
    result.protocol_name = get_protocol_name(protocol);
    result.ttl = data[8];
    result.total_length = ntohs(*(uint16_t*)(data + 2));
    result.is_fragmented = is_ipv4_fragmented(frag_off);
    result.fragment_offset = frag_off & 0x1FFF;
    result.dont_fragment = (frag_off & 0x4000) != 0;
    result.more_fragments = (frag_off & 0x2000) != 0;
    result.header_length = ihl * 4;
    result.next_layer_offset = start_offset + result.header_length;
    result.has_options = (ihl > 5);
    
    // Create string representation
    std::ostringstream oss;
    oss << "IPv4 " << result.src_ip << " -> " << result.dst_ip
        << " [" << result.protocol_name << "]";
    
    if (result.is_fragmented) {
        oss << " FRAG";
    }
    
    if (result.has_options) {
        oss << " +opts";
    }
    
    result.info_string = oss.str();
    result.parsed = true;
    
    return result;
}

L3Info L3Parser::parse_ipv6(const std::vector<uint8_t>& packet_data, size_t start_offset) {
    L3Info result = {};
    
    if (packet_data.size() < start_offset + 40) {
        result.parsed = false;
        return result;
    }

    const uint8_t* data = packet_data.data() + start_offset;
    
    uint8_t next_header = data[6];
    const uint8_t* src_addr = data + 8;
    const uint8_t* dst_addr = data + 24;
    uint32_t version_tc_fl = ntohl(*(uint32_t*)(data));
    
    // Fill IPv6 specific fields
    result.ip_version = 6;
    result.src_ip = ipv6_to_string(src_addr);
    result.dst_ip = ipv6_to_string(dst_addr);
    result.next_protocol = next_header;
    result.protocol_name = get_protocol_name(next_header);
    result.hop_limit = data[7];
    result.payload_length = ntohs(*(uint16_t*)(data + 4));
    result.flow_label = version_tc_fl & 0x000FFFFF;
    result.header_length = 40; // Base IPv6 header
    result.next_layer_offset = start_offset + 40;
    result.has_options = false; // TODO: Check for extension headers
    result.is_fragmented = false; // TODO: Check fragment extension header
    
    // Create string representation
    std::ostringstream oss;
    oss << "IPv6 " << result.src_ip << " -> " << result.dst_ip
        << " [" << result.protocol_name << "]";
    
    result.info_string = oss.str();
    result.parsed = true;
    
    return result;
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
