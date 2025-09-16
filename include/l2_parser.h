#pragma once

#include <string>
#include <vector>
#include <stdint.h>

/**
 * Layer 2 (Ethernet) Parser
 * 
 * Stateless parser for Ethernet frames and VLAN tags
 */
class L2Parser {
public:
    /**
     * Parse Ethernet frame and return string representation
     * @param packet_data Vector containing the packet data
     * @param start_offset Offset in the vector where L2 header starts (usually 0)
     * @return String representation of Ethernet frame, or empty string if parsing fails
     */
    static std::string parse(const std::vector<uint8_t>& packet_data, size_t start_offset = 0);

private:
    /**
     * Convert MAC address to string
     * @param mac 6-byte MAC address
     * @return MAC address string in format XX:XX:XX:XX:XX:XX
     */
    static std::string mac_to_string(const uint8_t mac[6]);

    /**
     * Get protocol name from EtherType
     * @param ether_type EtherType value
     * @return Protocol name string
     */
    static std::string get_protocol_name(uint16_t ether_type);
};
