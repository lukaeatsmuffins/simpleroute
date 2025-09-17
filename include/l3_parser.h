#pragma once

#include <string>
#include <vector>
#include <stdint.h>

/**
 * Layer 3 (IP) information structure
 */
struct L3Info {
    // Parsing success
    bool parsed;                    // Whether parsing was successful
    
    // IP version
    uint8_t ip_version;             // IP version (4 or 6, 0 if not IP)
    
    // Addresses
    std::string src_ip;             // Source IP address
    std::string dst_ip;             // Destination IP address
    
    // Protocol information
    uint8_t next_protocol;          // Next layer protocol number
    std::string protocol_name;      // Protocol name (TCP, UDP, ICMP, etc.)
    
    // IPv4 specific
    uint8_t ttl;                    // Time to Live (IPv4 only)
    uint16_t total_length;          // Total packet length (IPv4)
    bool is_fragmented;             // Packet is fragmented (IPv4 only)
    uint16_t fragment_offset;       // Fragment offset (IPv4)
    bool dont_fragment;             // Don't Fragment flag (IPv4)
    bool more_fragments;            // More Fragments flag (IPv4)
    
    // IPv6 specific
    uint8_t hop_limit;              // Hop limit (IPv6 only)
    uint16_t payload_length;        // Payload length (IPv6)
    uint32_t flow_label;            // Flow label (IPv6)
    
    // Header information
    uint32_t header_length;         // L3 header length in bytes
    uint32_t next_layer_offset;     // Offset to next layer header
    bool has_options;               // Whether IP options/extensions are present
    
    // String representation
    std::string info_string;        // Formatted string representation
};

/**
 * Layer 3 (IP) Parser
 * 
 * Stateless parser for IPv4 and IPv6 headers
 */
class L3Parser {
public:
    /**
     * IP version enumeration
     */
    enum IPVersion : uint8_t {
        IPV4 = 4,
        IPV6 = 6
    };
    /**
     * Parse IP packet (IPv4 or IPv6) and return detailed information
     * @param packet_data Vector containing the packet data
     * @param start_offset Offset in the vector where L3 header starts
     * @return L3Info structure with all extracted information
     */
    static L3Info parse(const std::vector<uint8_t>& packet_data, size_t start_offset);
    
    /**
     * Serialize L3 information to capture format
     * @param l3_info The L3 information to serialize
     * @return Serialized string in format "IPv4/IPv6;src_ip;dst_ip;protocol_num;ttl/hop_limit;length"
     */
    static std::string serialize(const L3Info& l3_info);

    /**
     * Deserialize L3 information from capture format
     * @param layer_string The serialized L3 layer string
     * @return L3Info structure with deserialized information
     */
    static L3Info deserialize(const std::string& layer_string);

private:
    /**
     * Parse IPv4 header
     * @param packet_data Vector containing the packet data
     * @param start_offset Offset where IPv4 header starts
     * @return L3Info structure with IPv4 information
     */
    static L3Info parse_ipv4(const std::vector<uint8_t>& packet_data, size_t start_offset);

    /**
     * Parse IPv6 header
     * @param packet_data Vector containing the packet data
     * @param start_offset Offset where IPv6 header starts
     * @return L3Info structure with IPv6 information
     */
    static L3Info parse_ipv6(const std::vector<uint8_t>& packet_data, size_t start_offset);

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
