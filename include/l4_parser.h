#ifndef L4_PARSER_H
#define L4_PARSER_H

#include <string>
#include <vector>
#include <stdint.h>

struct L4Info {
    // Parsing success.
    bool parsed;                    // Whether parsing was successful
    
    // Protocol information.
    uint8_t protocol_type;          // Protocol type (6=TCP, 17=UDP, etc.)
    std::string protocol_name;      // Protocol name (TCP, UDP, ICMP, etc.)
    
    // Port information (TCP/UDP only).
    uint16_t src_port;              // Source port (0 if not applicable)
    uint16_t dst_port;              // Destination port (0 if not applicable)
    std::string src_service;        // Source service name
    std::string dst_service;        // Destination service name
    
    // TCP specific.
    uint32_t sequence_number;       // TCP sequence number
    uint32_t ack_number;            // TCP acknowledgment number
    uint8_t tcp_flags;              // TCP flags byte
    std::string tcp_flags_string;   // TCP flags as string (SYN, ACK, etc.)
    uint16_t window_size;           // TCP window size
    bool has_tcp_options;           // TCP options present
    
    // UDP specific.
    uint16_t udp_length;            // UDP length field
    
    // ICMP specific.
    uint8_t icmp_type;              // ICMP type
    uint8_t icmp_code;              // ICMP code
    std::string icmp_type_name;     // ICMP type name
    std::string icmp_code_name;     // ICMP code name
    
    // Header information.
    uint32_t header_length;         // L4 header length in bytes
    uint32_t next_layer_offset;     // Offset to payload
    
    // String representation.
    std::string info_string;        // Formatted string representation
};

class L4Parser {
public:
    // Protocol enumeration for L4 protocols.
    enum Protocol : uint8_t {
        PROTO_UNKNOWN = 0,
        PROTO_ICMP = 1,
        PROTO_TCP = 6,
        PROTO_UDP = 17,
        PROTO_ICMPV6 = 58,
        PROTO_OSPF = 89,
        PROTO_SCTP = 132
    };
    
    // Parse transport layer protocol and return detailed information.
    static L4Info parse(const std::vector<uint8_t>& packet_data, size_t start_offset, uint8_t protocol);
    
    // Serialize L4 information to capture format.
    static std::string serialize(const L4Info& l4_info);

    // Deserialize L4 information from capture format.
    static L4Info deserialize(const std::string& layer_string);

private:
    // Parse TCP header.
    static L4Info parse_tcp(const std::vector<uint8_t>& packet_data, size_t start_offset);

    // Parse UDP header.
    static L4Info parse_udp(const std::vector<uint8_t>& packet_data, size_t start_offset);

    // Parse ICMP header.
    static L4Info parse_icmp(const std::vector<uint8_t>& packet_data, size_t start_offset);

    // Get TCP flags as string.
    static std::string tcp_flags_to_string(uint8_t flags);

    // Get service name for port number.
    static std::string get_service_name(uint16_t port);

    // Get protocol name from protocol number.
    static std::string get_protocol_name(uint8_t protocol);

    // Get protocol type enum from protocol name.
    static Protocol get_protocol_type(const std::string& protocol_name);
};

#endif
