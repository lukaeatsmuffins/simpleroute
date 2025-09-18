#pragma once

#include "parser.h"
#include <string>
#include <unordered_map>
#include <vector>
#include <memory>

// Packet Statistics Collection Class - Provides two main modes: Filter Mode and Grouping Mode.

// TODO:
// Verify if filter is working correctly.
// Verify if length filter works with payload or total length.

// Simple statistics for filtered packets.
struct FilterStats {
    uint64_t packet_count = 0;
    uint64_t total_bytes = 0;
    std::string filter_description;
};

// Filter criteria for packet filtering.
struct FilterCriteria {
    // L2 (Ethernet) filtering.
    std::string src_mac;            // Source MAC address
    std::string dst_mac;            // Destination MAC address
    uint16_t vlan_id = 0;           // VLAN ID (0 = any)
    
    // L3 (IP) filtering.
    std::string protocol;           // e.g., "tcp", "udp", "icmp"
    std::string src_ip;             // Source IP address
    std::string dst_ip;             // Destination IP address
    
    // L4 (Transport) filtering.
    uint16_t src_port = 0;          // Source port (0 = any)
    uint16_t dst_port = 0;          // Destination port (0 = any)
    
    // General filtering.
    uint32_t min_size = 0;         // Minimum packet size
    uint32_t max_size = 0;          // Maximum packet size
    
    // Helper methods.
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

// Grouping criteria for packet grouping.
enum class GroupBy {
    // L2 (Ethernet) grouping.
    SRC_MAC,        // Group by source MAC address
    DST_MAC,        // Group by destination MAC address
    VLAN_ID,        // Group by VLAN ID
    
    // L3 (IP) grouping.
    PROTOCOL,       // Group by protocol (TCP, UDP, ICMP, etc.)
    SRC_IP,         // Group by source IP
    DST_IP,         // Group by destination IP
    
    // L4 (Transport) grouping.
    SRC_PORT,       // Group by source port
    DST_PORT,       // Group by destination port
    
    // General grouping.
    PACKET_SIZE     // Group by packet size ranges
};

// Main statistics collection class.
class Stats {
public:
    // Constructor.
    Stats();
    
    // Destructor.
    ~Stats();
    
    // ===== FILTER MODE =====.
    
    // Set filter criteria from a filter string.
    bool setFilter(const std::string& filter_string);
    
    // Clear all filter criteria.
    void clearFilter();
    
    // Check if a packet matches the current filter criteria.
    bool matchesFilter(const ParsedPacket& packet) const;
    
    // Apply filter to packets from a capture file and return statistics.
    FilterStats applyFilter(const std::string& filename) const;
    
    // Group packets from a capture file by specified criteria.
    std::unordered_map<std::string, uint64_t> groupPackets(
        const std::string& filename, 
        GroupBy group_by
    ) const;
    
    // Get formatted grouping results from capture file.
    std::string getGroupingReport(
        const std::string& filename, 
        GroupBy group_by
    ) const;
    
    // Get current filter criteria.
    const FilterCriteria& getFilter() const { return filter_; }
    
    // Check if any filter is currently active.
    bool hasActiveFilter() const;

private:
    FilterCriteria filter_;
    
    // Parse filter string and populate FilterCriteria.
    bool parseFilterString(const std::string& filter_string);
    
    // Check if MAC address matches filter.
    bool macMatches(const std::string& packet_mac, const std::string& filter_mac) const;
    
    // Check if IP address matches filter (supports CIDR notation).
    bool ipMatches(const std::string& packet_ip, const std::string& filter_ip) const;
    
    // Get grouping key for a packet based on GroupBy criteria.
    std::string getGroupingKey(const ParsedPacket& packet, GroupBy group_by) const;
    
    // Get packet size range string for PACKET_SIZE grouping.
    std::string getSizeRange(uint32_t packet_size) const;
    
    // Format grouping results into a readable string.
    std::string formatGroupingResults(
        const std::unordered_map<std::string, uint64_t>& groups, 
        GroupBy group_by
    ) const;
};
