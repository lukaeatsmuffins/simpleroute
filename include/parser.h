#pragma once

#include "l2_parser.h"
#include "l3_parser.h"
#include "l4_parser.h"
#include <string>
#include <vector>
#include <stdint.h>

struct ParsedPacket {
    L2Info l2;
    L3Info l3;
    L4Info l4;
    
    uint32_t total_length;
    uint32_t payload_offset;
    uint32_t payload_length;
    
    bool has_l2() const { return l2.parsed; }
    bool has_l3() const { return l3.parsed; }
    bool has_l4() const { return l4.parsed; }
    
    const std::string& src_mac() const { return l2.src_mac; }
    const std::string& dst_mac() const { return l2.dst_mac; }
    const std::string& src_ip() const { return l3.src_ip; }
    const std::string& dst_ip() const { return l3.dst_ip; }
    uint16_t src_port() const { return l4.src_port; }
    uint16_t dst_port() const { return l4.dst_port; }
    const std::string& tcp_flags() const { return l4.tcp_flags_string; }
};

class Parser {
public:
    static ParsedPacket parse_packet(const std::vector<uint8_t>& packet_data, size_t start_offset = 0);
    static std::string get_summary(const ParsedPacket& parsed);
    static std::string get_details(const ParsedPacket& parsed);
    static std::string get_flow_id(const ParsedPacket& parsed);
    static bool is_protocol(const ParsedPacket& parsed, const std::string& protocol);
    static uint32_t get_header_overhead(const ParsedPacket& parsed);
    static bool has_payload(const ParsedPacket& parsed);
    static std::string get_protocol_stack(const ParsedPacket& parsed);
    static std::string serialize_packet(const ParsedPacket& parsed);
    static ParsedPacket deserialize_packet(const std::string& line);
    
private:
    static void calculate_payload_info(const std::vector<uint8_t>& packet_data,
                                      size_t start_offset, ParsedPacket& result);
};