#pragma once

#include <string>
#include <vector>
#include <stdint.h>

/**
 * Layer 4 (Transport) Parser
 * 
 * Stateless parser for TCP, UDP, and ICMP headers
 */
class L4Parser {
public:
    /**
     * Protocol enumeration for L4 protocols
     */
    enum Protocol : uint8_t {
        PROTO_ICMP = 1,
        PROTO_TCP = 6,
        PROTO_UDP = 17,
        PROTO_ICMPV6 = 58,
        PROTO_OSPF = 89,
        PROTO_SCTP = 132
    };
    /**
     * Parse transport layer protocol and return string representation
     * @param packet_data Vector containing the packet data
     * @param start_offset Offset in the vector where L4 header starts
     * @param protocol IP protocol number (6=TCP, 17=UDP, 1=ICMP, etc.)
     * @return String representation of transport header, or empty string if parsing fails
     */
    static std::string parse(const std::vector<uint8_t>& packet_data, size_t start_offset, uint8_t protocol);

private:
    /**
     * Parse TCP header
     * @param packet_data Vector containing the packet data
     * @param start_offset Offset where TCP header starts
     * @return String representation of TCP header
     */
    static std::string parse_tcp(const std::vector<uint8_t>& packet_data, size_t start_offset);

    /**
     * Parse UDP header
     * @param packet_data Vector containing the packet data
     * @param start_offset Offset where UDP header starts
     * @return String representation of UDP header
     */
    static std::string parse_udp(const std::vector<uint8_t>& packet_data, size_t start_offset);

    /**
     * Parse ICMP header
     * @param packet_data Vector containing the packet data
     * @param start_offset Offset where ICMP header starts
     * @return String representation of ICMP header
     */
    static std::string parse_icmp(const std::vector<uint8_t>& packet_data, size_t start_offset);

    /**
     * Get TCP flags as string
     * @param flags TCP flags byte
     * @return String representation of TCP flags
     */
    static std::string tcp_flags_to_string(uint8_t flags);

    /**
     * Get service name for port number
     * @param port Port number
     * @return Well-known service name or port number as string
     */
    static std::string get_service_name(uint16_t port);

    /**
     * Get protocol name from protocol number
     * @param protocol IP protocol number
     * @return Protocol name string
     */
    static std::string get_protocol_name(uint8_t protocol);
};
