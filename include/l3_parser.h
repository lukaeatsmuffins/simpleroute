#pragma once

#include <string>
#include <vector>
#include <stdint.h>

/**
 * Layer 3 (IP) Parser
 * 
 * Stateless parser for IPv4 and IPv6 headers
 */
class L3Parser {
public:
    /**
     * Parse IP packet (IPv4 or IPv6) and return string representation
     * @param packet_data Vector containing the packet data
     * @param start_offset Offset in the vector where L3 header starts
     * @return String representation of IP header, or empty string if parsing fails
     */
    static std::string parse(const std::vector<uint8_t>& packet_data, size_t start_offset);

private:
    /**
     * Parse IPv4 header
     * @param packet_data Vector containing the packet data
     * @param start_offset Offset where IPv4 header starts
     * @return String representation of IPv4 header
     */
    static std::string parse_ipv4(const std::vector<uint8_t>& packet_data, size_t start_offset);

    /**
     * Parse IPv6 header
     * @param packet_data Vector containing the packet data
     * @param start_offset Offset where IPv6 header starts
     * @return String representation of IPv6 header
     */
    static std::string parse_ipv6(const std::vector<uint8_t>& packet_data, size_t start_offset);

    /**
     * Convert IPv4 address to string
     * @param addr IPv4 address in network byte order
     * @return IP address string in dotted decimal notation
     */
    static std::string ipv4_to_string(const uint32_t addr);

    /**
     * Convert IPv6 address to string
     * @param addr 16-byte IPv6 address
     * @return IPv6 address string
     */
    static std::string ipv6_to_string(const uint8_t addr[16]);

    /**
     * Get protocol name from IP protocol number
     * @param protocol IP protocol number
     * @return Protocol name string
     */
    static std::string get_protocol_name(const uint8_t protocol);

    /**
     * Check if IPv4 packet is fragmented
     * @param frag_off Fragment offset field from IPv4 header
     * @return true if packet is fragmented
     */
    static bool is_ipv4_fragmented(const uint16_t frag_off);
};
