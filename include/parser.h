#pragma once

#include "l2_parser.h"
#include "l3_parser.h"
#include "l4_parser.h"
#include <string>
#include <vector>
#include <stdint.h>

// Comprehensive Packet Parser - Provides a unified interface to parse complete network packets.

// Parsed packet result containing information from all layers.
struct ParsedPacket {
    // Layer information structures.
    L2Info l2;                  // L2 layer detailed information
    L3Info l3;                  // L3 layer detailed information
    L4Info l4;                  // L4 layer detailed information
    
    // Packet metadata.
    uint32_t total_length;      // Total packet length
    uint32_t payload_offset;    // Offset to application payload
    uint32_t payload_length;    // Application payload length
    
    // Convenience accessors (derived from layer info).
    bool has_l2() const { return l2.parsed; }
    bool has_l3() const { return l3.parsed; }
    bool has_l4() const { return l4.parsed; }
    
    // Quick access to common fields.
    const std::string& src_mac() const { return l2.src_mac; }
    const std::string& dst_mac() const { return l2.dst_mac; }
    const std::string& src_ip() const { return l3.src_ip; }
    const std::string& dst_ip() const { return l3.dst_ip; }
    uint16_t src_port() const { return l4.src_port; }
    uint16_t dst_port() const { return l4.dst_port; }
    const std::string& tcp_flags() const { return l4.tcp_flags_string; }
};

// Main packet parser class - Provides methods to parse complete packets and extract structured information.
// TODO: Remove unused methods at the end.
class Parser {
public:
    // Parse a complete network packet.
    static ParsedPacket parse_packet(const std::vector<uint8_t>& packet_data, size_t start_offset = 0);
    
    // Get a summary string of the parsed packet.
    static std::string get_summary(const ParsedPacket& parsed);
    
    // Get detailed multi-line information about the packet.
    static std::string get_details(const ParsedPacket& parsed);
    
    // Get flow identifier for connection tracking.
    static std::string get_flow_id(const ParsedPacket& parsed);
    
    // Check if packet is a specific protocol type.
    static bool is_protocol(const ParsedPacket& parsed, const std::string& protocol);
    
    // Get total header overhead (all layers).
    static uint32_t get_header_overhead(const ParsedPacket& parsed);
    
    // Check if packet has application payload.
    static bool has_payload(const ParsedPacket& parsed);
    
    // Get protocol stack as string.
    static std::string get_protocol_stack(const ParsedPacket& parsed);
    
    // Serialize packet to capture file format.
    static std::string serialize_packet(const ParsedPacket& parsed);
    
    // Deserialize packet from capture file format.
    static ParsedPacket deserialize_packet(const std::string& line);

private:
    // Calculate payload information from parsed layers.
    static void calculate_payload_info(const std::vector<uint8_t>& packet_data,
                                      size_t start_offset, ParsedPacket& result);
};