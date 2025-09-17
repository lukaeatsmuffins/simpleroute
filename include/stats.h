#pragma once

#include "parser.h"
#include <string>
#include <unordered_map>
#include <vector>
#include <memory>

/**
 * Packet Statistics Collection Class
 * 
 * Provides two main modes:
 * 1. Filter Mode: Apply filter and show stats for matching packets
 * 2. Grouping Mode: Group packets by criteria and show counts per group
 */

/**
 * Simple statistics for filtered packets
 */
struct FilterStats {
    uint64_t packet_count = 0;
    uint64_t total_bytes = 0;
    std::string filter_description;
};

/**
 * Filter criteria for packet filtering
 */
struct FilterCriteria {
    // L2 (Ethernet) filtering
    std::string src_mac;            // Source MAC address
    std::string dst_mac;            // Destination MAC address
    uint16_t vlan_id = 0;           // VLAN ID (0 = any)
    
    // L3 (IP) filtering
    std::string protocol;           // e.g., "tcp", "udp", "icmp"
    std::string src_ip;             // Source IP address
    std::string dst_ip;             // Destination IP address
    
    // L4 (Transport) filtering
    uint16_t src_port = 0;          // Source port (0 = any)
    uint16_t dst_port = 0;          // Destination port (0 = any)
    
    // General filtering
    uint32_t min_size = 0;         // Minimum packet size
    uint32_t max_size = 0;          // Maximum packet size
    
    // Helper methods
    bool has_mac_filter() const { return !src_mac.empty() || !dst_mac.empty(); }
    bool has_vlan_filter() const { return vlan_id != 0; }
    bool has_protocol() const { return !protocol.empty(); }
    bool has_ip_filter() const { return !src_ip.empty() || !dst_ip.empty(); }
    bool has_port_filter() const { return src_port != 0 || dst_port != 0; }
    bool has_size_filter() const { return min_size > 0 || max_size > 0; }
    bool has_any_filter() const { 
        return has_mac_filter() || has_vlan_filter() ||
               has_protocol() || has_ip_filter() || has_port_filter() || has_size_filter(); 
    }
};

/**
 * Grouping criteria for packet grouping
 */
enum class GroupBy {
    // L2 (Ethernet) grouping
    SRC_MAC,        // Group by source MAC address
    DST_MAC,        // Group by destination MAC address
    VLAN_ID,        // Group by VLAN ID
    
    // L3 (IP) grouping
    PROTOCOL,       // Group by protocol (TCP, UDP, ICMP, etc.)
    SRC_IP,         // Group by source IP
    DST_IP,         // Group by destination IP
    
    // L4 (Transport) grouping
    SRC_PORT,       // Group by source port
    DST_PORT,       // Group by destination port
    
    // General grouping
    PACKET_SIZE     // Group by packet size ranges
};

/**
 * Main statistics collection class
 */
class Stats {
public:
    /**
     * Constructor
     */
    Stats();
    
    /**
     * Destructor
     */
    ~Stats();
    
    // ===== FILTER MODE =====
    
    /**
     * Set filter criteria from a filter string
     * @param filter_string Filter string in format: "protocol=TCP src_ip=192.168.1.0/24 dst_port=80"
     * @return true if filter was parsed successfully, false otherwise
     */
    bool setFilter(const std::string& filter_string);
    
    /**
     * Clear all filter criteria
     */
    void clearFilter();
    
    /**
     * Check if a packet matches the current filter criteria
     * @param packet The parsed packet to check
     * @return true if packet matches filter, false otherwise
     */
    bool matchesFilter(const ParsedPacket& packet) const;
    
    /**
     * Apply filter to a collection of packets and return statistics
     * @param packets Vector of parsed packets to filter
     * @return FilterStats containing count and bytes of matching packets
     */
    FilterStats applyFilter(const std::vector<ParsedPacket>& packets) const;
    
    /**
     * Get current filter criteria
     * @return Reference to current FilterCriteria
     */
    const FilterCriteria& getFilter() const { return filter_; }
    
    /**
     * Check if any filter is currently active
     * @return true if any filter criteria is set
     */
    bool hasActiveFilter() const;
    
    // ===== GROUPING MODE =====
    
    /**
     * Group packets by specified criteria and return counts per group
     * @param packets Vector of parsed packets to group
     * @param group_by Criteria to group by
     * @return Map of group key to packet count
     */
    std::unordered_map<std::string, uint64_t> groupPackets(
        const std::vector<ParsedPacket>& packets, 
        GroupBy group_by
    ) const;
    
    /**
     * Get formatted grouping results
     * @param packets Vector of parsed packets to group
     * @param group_by Criteria to group by
     * @return Formatted string showing groups and counts
     */
    std::string getGroupingReport(
        const std::vector<ParsedPacket>& packets, 
        GroupBy group_by
    ) const;

private:
    FilterCriteria filter_;
    
    /**
     * Parse filter string and populate FilterCriteria
     * @param filter_string The filter string to parse
     * @return true if parsing was successful
     */
    bool parseFilterString(const std::string& filter_string);
    
    /**
     * Check if MAC address matches filter
     * @param packet_mac The MAC address from the packet
     * @param filter_mac The MAC address from the filter
     * @return true if MAC matches filter
     */
    bool macMatches(const std::string& packet_mac, const std::string& filter_mac) const;
    
    /**
     * Check if IP address matches filter (supports CIDR notation)
     * @param packet_ip The IP address from the packet
     * @param filter_ip The IP address/subnet from the filter
     * @return true if IP matches filter
     */
    bool ipMatches(const std::string& packet_ip, const std::string& filter_ip) const;
    
    /**
     * Get grouping key for a packet based on GroupBy criteria
     * @param packet The parsed packet
     * @param group_by The grouping criteria
     * @return String key for grouping
     */
    std::string getGroupingKey(const ParsedPacket& packet, GroupBy group_by) const;
    
    /**
     * Get packet size range string for PACKET_SIZE grouping
     * @param packet_size The packet size
     * @return Size range string (e.g., "64-128", "1024+")
     */
    std::string getSizeRange(uint32_t packet_size) const;
};
