#pragma once

#include "parser.h"
#include <string>
#include <unordered_map>
#include <vector>
#include <memory>

struct FilterStats {
    uint64_t packet_count = 0;
    uint64_t total_bytes = 0;
    std::string filter_description;
};

struct FilterCriteria {
    std::string src_mac;
    std::string dst_mac;
    uint16_t vlan_id = 0;
    
    std::string protocol;
    std::string src_ip;
    std::string dst_ip;
    
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    
    uint32_t min_size = 0;
    uint32_t max_size = 0;
    
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

enum class GroupBy {
    SRC_MAC,
    DST_MAC,
    VLAN_ID,
    PROTOCOL,
    SRC_IP,
    DST_IP,
    SRC_PORT,
    DST_PORT,
    PACKET_SIZE
};

class Stats {
public:
    Stats();
    ~Stats();
    
    bool setFilter(const std::string& filter_string);
    void clearFilter();
    bool matchesFilter(const ParsedPacket& packet) const;
    FilterStats applyFilter(const std::string& filename) const;
    std::unordered_map<std::string, uint64_t> groupPackets(
        const std::string& filename, 
        GroupBy group_by
    ) const;
    std::string getGroupingReport(
        const std::string& filename, 
        GroupBy group_by
    ) const;
    const FilterCriteria& getFilter() const { return filter_; }
    bool hasActiveFilter() const;

private:
    FilterCriteria filter_;
    
    bool parseFilterString(const std::string& filter_string);
    bool macMatches(const std::string& packet_mac, const std::string& filter_mac) const;
    bool ipMatches(const std::string& packet_ip, const std::string& filter_ip) const;
    std::string getGroupingKey(const ParsedPacket& packet, GroupBy group_by) const;
    std::string getSizeRange(uint32_t packet_size) const;
    std::string formatGroupingResults(
        const std::unordered_map<std::string, uint64_t>& groups, 
        GroupBy group_by
    ) const;
};
