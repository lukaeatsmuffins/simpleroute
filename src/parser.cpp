#include "parser.h"
#include <sstream>
#include <algorithm>
#include <cctype>

ParsedPacket Parser::parse_packet(const std::vector<uint8_t>& packet_data, size_t start_offset) {
    ParsedPacket result = {};
    
    // Parse L2 (Ethernet) layer
    result.l2 = L2Parser::parse(packet_data, start_offset);
    
    // Parse L3 (IP) layer if L2 was successful
    if (result.l2.parsed) {
        result.l3 = L3Parser::parse(packet_data, result.l2.next_layer_offset);       
    }
    
    // Parse L4 (Transport) layer if L3 was successful
    if (result.l3.parsed) {
        result.l4 = L4Parser::parse(packet_data, result.l3.next_layer_offset, result.l3.next_protocol);
    }

    // Calculate payload information
    calculate_payload_info(packet_data, start_offset, result);
    
    return result;
}

std::string Parser::get_summary(const ParsedPacket& parsed) {
    std::ostringstream oss;
    
    if (parsed.has_l2()) {
        oss << "ETH";
        if (parsed.l2.has_vlan) {
            oss << "(VLAN:" << parsed.l2.vlan_id << ")";
        }
    }
    
    if (parsed.has_l3()) {
        oss << " -> ";
        if (parsed.l3.ip_version == 4) {
            oss << "IPv4";
        } else if (parsed.l3.ip_version == 6) {
            oss << "IPv6";
        } else {
            oss << "IP";
        }
    }
    
    if (parsed.has_l4()) {
        oss << " -> " << parsed.l4.protocol_name;
        if (parsed.l4.src_port != 0 || parsed.l4.dst_port != 0) {
            oss << "(" << parsed.l4.src_port << "->" << parsed.l4.dst_port << ")";
        }
    }
    
    return oss.str();
}

std::string Parser::get_details(const ParsedPacket& parsed) {
    std::ostringstream oss;
    
    oss << "=== Packet Details ===" << std::endl;
    oss << "Total Length: " << parsed.total_length << " bytes" << std::endl;
    oss << "Payload Length: " << parsed.payload_length << " bytes" << std::endl;
    oss << "Header Overhead: " << get_header_overhead(parsed) << " bytes" << std::endl;
    oss << std::endl;
    
    if (parsed.has_l2()) {
        oss << "L2 (Ethernet):" << std::endl;
        oss << "  " << parsed.l2.info_string << std::endl;
        if (parsed.l2.has_vlan) {
            oss << "  VLAN ID: " << parsed.l2.vlan_id << std::endl;
            oss << "  VLAN Priority: " << static_cast<int>(parsed.l2.vlan_priority) << std::endl;
        }
        oss << std::endl;
    }
    
    if (parsed.has_l3()) {
        oss << "L3 (IP):" << std::endl;
        oss << "  " << parsed.l3.info_string << std::endl;
        oss << "  Version: " << static_cast<int>(parsed.l3.ip_version) << std::endl;
        if (parsed.l3.ip_version == 4) {
            oss << "  TTL: " << static_cast<int>(parsed.l3.ttl) << std::endl;
            oss << "  Total Length: " << parsed.l3.total_length << std::endl;
            oss << "  Fragmented: " << (parsed.l3.is_fragmented ? "Yes" : "No") << std::endl;
        } else if (parsed.l3.ip_version == 6) {
            oss << "  Hop Limit: " << static_cast<int>(parsed.l3.hop_limit) << std::endl;
            oss << "  Payload Length: " << parsed.l3.payload_length << std::endl;
            oss << "  Flow Label: 0x" << std::hex << parsed.l3.flow_label << std::dec << std::endl;
        }
        oss << std::endl;
    }
    
    if (parsed.has_l4()) {
        oss << "L4 (" << parsed.l4.protocol_name << "):" << std::endl;
        oss << "  " << parsed.l4.info_string << std::endl;
        
        if (parsed.l4.protocol_type == L4Parser::PROTO_TCP) {
            oss << "  Sequence: " << parsed.l4.sequence_number << std::endl;
            oss << "  ACK: " << parsed.l4.ack_number << std::endl;
            oss << "  Window: " << parsed.l4.window_size << std::endl;
            oss << "  Options: " << (parsed.l4.has_tcp_options ? "Yes" : "No") << std::endl;
        } else if (parsed.l4.protocol_type == L4Parser::PROTO_UDP) {
            oss << "  Length: " << parsed.l4.udp_length << std::endl;
        } else if (parsed.l4.protocol_type == L4Parser::PROTO_ICMP) {
            oss << "  Type: " << static_cast<int>(parsed.l4.icmp_type) << std::endl;
            oss << "  Code: " << static_cast<int>(parsed.l4.icmp_code) << std::endl;
        }
        oss << std::endl;
    }
    
    if (has_payload(parsed)) {
        oss << "Payload: " << parsed.payload_length << " bytes starting at offset " << parsed.payload_offset << std::endl;
    } else {
        oss << "No application payload detected" << std::endl;
    }
    
    return oss.str();
}

std::string Parser::get_flow_id(const ParsedPacket& parsed) {
    std::ostringstream oss;
    
    if (parsed.has_l3() && parsed.has_l4()) {
        // Use IP addresses and ports for flow identification
        oss << parsed.src_ip() << ":" << parsed.src_port();
        oss << " <-> ";
        oss << parsed.dst_ip() << ":" << parsed.dst_port();
    } else if (parsed.has_l3()) {
        // Use only IP addresses if no L4
        oss << parsed.src_ip() << " <-> " << parsed.dst_ip();
    } else if (parsed.has_l2()) {
        // Use MAC addresses if no L3
        oss << parsed.src_mac() << " <-> " << parsed.dst_mac();
    } else {
        oss << "Unknown flow";
    }
    
    return oss.str();
}

bool Parser::is_protocol(const ParsedPacket& parsed, const std::string& protocol) {
    std::string lower_protocol = protocol;
    std::transform(lower_protocol.begin(), lower_protocol.end(), lower_protocol.begin(), ::tolower);
    
    // Check L2 protocols
    if (parsed.has_l2()) {
        std::string l2_protocol = parsed.l2.protocol_name;
        std::transform(l2_protocol.begin(), l2_protocol.end(), l2_protocol.begin(), ::tolower);
        if (l2_protocol == lower_protocol) return true;
        
        // For VLAN packets, also check if the protocol is "VLAN"
        if (parsed.l2.has_vlan && lower_protocol == "vlan") {
            return true;
        }
    }
    
    // Check L3 protocols
    if (parsed.has_l3()) {
        std::string l3_protocol = parsed.l3.protocol_name;
        std::transform(l3_protocol.begin(), l3_protocol.end(), l3_protocol.begin(), ::tolower);
        if (l3_protocol == lower_protocol) return true;
    }
    
    // Check L4 protocols
    if (parsed.has_l4()) {
        std::string l4_protocol = parsed.l4.protocol_name;
        std::transform(l4_protocol.begin(), l4_protocol.end(), l4_protocol.begin(), ::tolower);
        if (l4_protocol == lower_protocol) return true;
    }
    
    return false;
}

uint32_t Parser::get_header_overhead(const ParsedPacket& parsed) {
    uint32_t overhead = 0;
    
    if (parsed.has_l2()) {
        overhead += parsed.l2.header_length;
    }
    
    if (parsed.has_l3()) {
        overhead += parsed.l3.header_length;
    }
    
    if (parsed.has_l4()) {
        overhead += parsed.l4.header_length;
    }
    
    return overhead;
}

bool Parser::has_payload(const ParsedPacket& parsed) {
    return parsed.payload_length > 0;
}

std::string Parser::get_protocol_stack(const ParsedPacket& parsed) {
    std::ostringstream oss;
    bool first = true;
    
    if (parsed.has_l2()) {
        if (!first) oss << "/";
        oss << "Ethernet";
        if (parsed.l2.has_vlan) {
            oss << "(VLAN)";
        }
        first = false;
    }
    
    if (parsed.has_l3()) {
        if (!first) oss << "/";
        if (parsed.l3.ip_version == 4) {
            oss << "IPv4";
        } else if (parsed.l3.ip_version == 6) {
            oss << "IPv6";
        } else {
            oss << "IP";
        }
        first = false;
    }
    
    if (parsed.has_l4()) {
        if (!first) oss << "/";
        oss << parsed.l4.protocol_name;
        first = false;
    }
    
    return oss.str();
}

void Parser::calculate_payload_info(const std::vector<uint8_t>& packet_data, size_t start_offset, ParsedPacket& result) {
    result.total_length = packet_data.size() - start_offset;
    
    // Calculate payload offset and length
    if (result.has_l4()) {
        result.payload_offset = result.l4.next_layer_offset;
        result.payload_length = result.total_length - (result.payload_offset - start_offset);
    } else if (result.has_l3()) {
        result.payload_offset = result.l3.next_layer_offset;
        result.payload_length = result.total_length - (result.payload_offset - start_offset);
    } else if (result.has_l2()) {
        result.payload_offset = result.l2.next_layer_offset;
        result.payload_length = result.total_length - (result.payload_offset - start_offset);
    } else {
        result.payload_offset = start_offset;
        result.payload_length = result.total_length;
    }
    
    // Ensure payload length is not negative
    if (result.payload_length > result.total_length) {
        result.payload_length = 0;
    }
}
