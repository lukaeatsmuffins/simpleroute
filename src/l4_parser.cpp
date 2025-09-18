#include "l4_parser.h"
#include <sstream>
#include <arpa/inet.h>

L4Info L4Parser::parse(const std::vector<uint8_t>& packet_data, size_t start_offset, uint8_t protocol) {
    L4Info result = {};
    result.protocol_type = protocol;
    result.protocol_name = get_protocol_name(protocol);
    
    switch (protocol) {
        case PROTO_TCP: return parse_tcp(packet_data, start_offset);
        case PROTO_UDP: return parse_udp(packet_data, start_offset);
        case PROTO_ICMP: case PROTO_ICMPV6: return parse_icmp(packet_data, start_offset);
        default: 
            result.parsed = false;
            result.info_string = result.protocol_name;
            return result;
    }
}

L4Info L4Parser::parse_tcp(const std::vector<uint8_t>& packet_data, size_t start_offset) {
    L4Info result = {};
    result.protocol_type = PROTO_TCP;
    result.protocol_name = "TCP";
    
    if (packet_data.size() < start_offset + 20) {
        result.parsed = false;
        return result;
    }

    const uint8_t* data = packet_data.data() + start_offset;
    
    result.src_port = ntohs(*(uint16_t*)(data));
    result.dst_port = ntohs(*(uint16_t*)(data + 2));
    result.src_service = get_service_name(result.src_port);
    result.dst_service = get_service_name(result.dst_port);
    result.sequence_number = ntohl(*(uint32_t*)(data + 4));
    result.ack_number = ntohl(*(uint32_t*)(data + 8));
    result.tcp_flags = data[13];
    result.tcp_flags_string = tcp_flags_to_string(result.tcp_flags);
    result.window_size = ntohs(*(uint16_t*)(data + 14));
    
    uint8_t data_off = (data[12] >> 4) & 0x0F;
    result.header_length = data_off * 4;
    result.has_tcp_options = (data_off > 5);
    result.next_layer_offset = start_offset + result.header_length;
    
    // Create string representation.
    std::ostringstream oss;
    oss << "TCP " << result.src_service << " -> " << result.dst_service
        << " [" << result.tcp_flags_string << "] seq:" << result.sequence_number;
    
    if (result.has_tcp_options) {
        oss << " +opts";
    }
    
    result.info_string = oss.str();
    result.parsed = true;
    
    return result;
}

L4Info L4Parser::parse_udp(const std::vector<uint8_t>& packet_data, size_t start_offset) {
    L4Info result = {};
    result.protocol_type = PROTO_UDP;
    result.protocol_name = "UDP";
    
    if (packet_data.size() < start_offset + 8) {
        result.parsed = false;
        return result;
    }

    const uint8_t* data = packet_data.data() + start_offset;
    
    result.src_port = ntohs(*(uint16_t*)(data));
    result.dst_port = ntohs(*(uint16_t*)(data + 2));
    result.src_service = get_service_name(result.src_port);
    result.dst_service = get_service_name(result.dst_port);
    result.udp_length = ntohs(*(uint16_t*)(data + 4));
    result.header_length = 8;
    result.next_layer_offset = start_offset + 8;
    
    // Create string representation.
    std::ostringstream oss;
    oss << "UDP " << result.src_service << " -> " << result.dst_service
        << " len:" << result.udp_length;
    
    result.info_string = oss.str();
    result.parsed = true;
    
    return result;
}

L4Info L4Parser::parse_icmp(const std::vector<uint8_t>& packet_data, size_t start_offset) {
    L4Info result = {};
    result.protocol_type = PROTO_ICMP;
    result.protocol_name = "ICMP";
    
    if (packet_data.size() < start_offset + 8) {
        result.parsed = false;
        return result;
    }

    const uint8_t* data = packet_data.data() + start_offset;
    
    result.icmp_type = data[0];
    result.icmp_code = data[1];
    result.src_port = 0;
    result.dst_port = 0;
    result.header_length = 8;
    result.next_layer_offset = start_offset + 8;
    
    // Create string representation.
    std::ostringstream oss;
    oss << "ICMP type:" << static_cast<unsigned>(result.icmp_type) 
        << " code:" << static_cast<unsigned>(result.icmp_code);
    
    result.info_string = oss.str();
    result.parsed = true;
    
    return result;
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

std::string L4Parser::serialize(const L4Info& l4_info) {
    if (!l4_info.parsed) {
        return "";
    }
    
    std::ostringstream oss;
    oss << l4_info.protocol_name << ";" << l4_info.src_port << ";" << l4_info.dst_port;
    
    // Add protocol-specific data.
    switch (static_cast<Protocol>(l4_info.protocol_type)) {
        case Protocol::PROTO_TCP:
            oss << ";" << l4_info.tcp_flags_string << ";" << l4_info.window_size;
            break;
        case Protocol::PROTO_UDP:
            oss << ";" << l4_info.udp_length;
            break;
        case Protocol::PROTO_ICMP:
            oss << ";" << static_cast<int>(l4_info.icmp_type) << ";" << static_cast<int>(l4_info.icmp_code);
            break;
        case Protocol::PROTO_ICMPV6:
            oss << ";" << static_cast<int>(l4_info.icmp_type) << ";" << static_cast<int>(l4_info.icmp_code);
            break;
        default:
            // No additional data for other protocols.
            break;
    }
    
    return oss.str();
}

L4Info L4Parser::deserialize(const std::string& layer_string) {
    L4Info result = {};
    
    std::vector<std::string> fields;
    std::string current_field;
    
    // Split by ; to get fields.
    for (char c : layer_string) {
        if (c == ';') {
            fields.push_back(current_field);
            current_field.clear();
        } else {
            current_field += c;
        }
    }
    if (!current_field.empty()) {
        fields.push_back(current_field);
    }
    
    if (fields.size() >= 4) {
        std::string protocol_name = fields[0];
        
        result.parsed = true;
        result.protocol_name = protocol_name;
        result.protocol_type = static_cast<uint8_t>(get_protocol_type(protocol_name));
        result.src_port = std::stoi(fields[1]);
        result.dst_port = std::stoi(fields[2]);
        
        // Add protocol-specific data using enum-based switch.
        switch (static_cast<Protocol>(result.protocol_type)) {
            case PROTO_TCP:
                if (fields.size() >= 5) {
                    result.tcp_flags_string = fields[3];
                    result.window_size = std::stoi(fields[4]);
                }
                break;
            case PROTO_UDP:
                if (fields.size() >= 4) {
                    result.udp_length = std::stoi(fields[3]);
                }
                break;
            case PROTO_ICMP:
            case PROTO_ICMPV6:
                if (fields.size() >= 5) {
                    result.icmp_type = std::stoi(fields[3]);
                    result.icmp_code = std::stoi(fields[4]);
                }
                break;
            default:
                // No additional data for other protocols.
                break;
        }
    }
    
    return result;
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

L4Parser::Protocol L4Parser::get_protocol_type(const std::string& protocol_name) {
    if (protocol_name == "TCP") return PROTO_TCP;
    if (protocol_name == "UDP") return PROTO_UDP;
    if (protocol_name == "ICMP") return PROTO_ICMP;
    if (protocol_name == "ICMPv6") return PROTO_ICMPV6;
    if (protocol_name == "OSPF") return PROTO_OSPF;
    if (protocol_name == "SCTP") return PROTO_SCTP;
    
    // Default to ICMP for unknown protocols.
    return PROTO_ICMP;
}
