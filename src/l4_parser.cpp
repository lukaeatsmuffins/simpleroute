#include "l4_parser.h"
#include <sstream>
#include <arpa/inet.h>

std::string L4Parser::parse(const std::vector<uint8_t>& packet_data, size_t start_offset, uint8_t protocol) {
    switch (protocol) {
        case PROTO_TCP: return parse_tcp(packet_data, start_offset);
        case PROTO_UDP: return parse_udp(packet_data, start_offset);
        case PROTO_ICMP: case PROTO_ICMPV6: return parse_icmp(packet_data, start_offset);
        default: return get_protocol_name(protocol);
    }
}

std::string L4Parser::parse_tcp(const std::vector<uint8_t>& packet_data, size_t start_offset) {
    if (packet_data.size() < start_offset + 20) {
        return "";
    }

    const uint8_t* data = packet_data.data() + start_offset;
    
    uint16_t src_port = ntohs(*(uint16_t*)(data));
    uint16_t dst_port = ntohs(*(uint16_t*)(data + 2));
    uint32_t seq = ntohl(*(uint32_t*)(data + 4));
    uint8_t flags = data[13];
    uint8_t data_off = (data[12] >> 4) & 0x0F;
    
    std::ostringstream oss;
    oss << "TCP " << get_service_name(src_port) << " -> " << get_service_name(dst_port)
        << " [" << tcp_flags_to_string(flags) << "] seq:" << seq;
    
    if (data_off > 5) {
        oss << " +opts";
    }
    
    return oss.str();
}

std::string L4Parser::parse_udp(const std::vector<uint8_t>& packet_data, size_t start_offset) {
    if (packet_data.size() < start_offset + 8) {
        return "";
    }

    const uint8_t* data = packet_data.data() + start_offset;
    
    uint16_t src_port = ntohs(*(uint16_t*)(data));
    uint16_t dst_port = ntohs(*(uint16_t*)(data + 2));
    uint16_t length = ntohs(*(uint16_t*)(data + 4));
    
    std::ostringstream oss;
    oss << "UDP " << get_service_name(src_port) << " -> " << get_service_name(dst_port)
        << " len:" << length;
    
    return oss.str();
}

std::string L4Parser::parse_icmp(const std::vector<uint8_t>& packet_data, size_t start_offset) {
    if (packet_data.size() < start_offset + 8) {
        return "";
    }

    const uint8_t* data = packet_data.data() + start_offset;
    
    uint8_t type = data[0];
    uint8_t code = data[1];
    
    std::ostringstream oss;
    oss << "ICMP type:" << static_cast<unsigned>(type) << " code:" << static_cast<unsigned>(code);
    
    return oss.str();
}

std::string L4Parser::tcp_flags_to_string(uint8_t flags) {
    std::string result;
    if (flags & 0x01) result += "F";  // FIN
    if (flags & 0x02) result += "S";  // SYN
    if (flags & 0x04) result += "R";  // RST
    if (flags & 0x08) result += "P";  // PSH
    if (flags & 0x10) result += "A";  // ACK
    if (flags & 0x20) result += "U";  // URG
    if (flags & 0x40) result += "E";  // ECE
    if (flags & 0x80) result += "C";  // CWR
    return result.empty() ? "." : result;
}

std::string L4Parser::get_service_name(uint16_t port) {
    switch (port) {
        case 20: return "ftp-data";
        case 21: return "ftp";
        case 22: return "ssh";
        case 23: return "telnet";
        case 25: return "smtp";
        case 53: return "dns";
        case 67: return "dhcp-s";
        case 68: return "dhcp-c";
        case 80: return "http";
        case 123: return "ntp";
        case 161: return "snmp";
        case 443: return "https";
        default: return std::to_string(port);
    }
}

std::string L4Parser::get_protocol_name(uint8_t protocol) {
    switch (protocol) {
        case PROTO_ICMP: return "ICMP";
        case PROTO_TCP: return "TCP";
        case PROTO_UDP: return "UDP";
        case PROTO_ICMPV6: return "ICMPv6";
        case PROTO_OSPF: return "OSPF";
        case PROTO_SCTP: return "SCTP";
        default: return "proto-" + std::to_string(protocol);
    }
}
