#include "stats.h"
#include "parser.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iostream>

Stats::Stats() {
    // Initialize with empty filter.
}

Stats::~Stats() {
    // Nothing to clean up.
}

bool Stats::setFilter(const std::string& filter_string) {
    clearFilter();
    return parseFilterString(filter_string);
}

void Stats::clearFilter() {
    filter_ = FilterCriteria{};
}

bool Stats::parseFilterString(const std::string& filter_string) {
    if (filter_string.empty()) {
        return true;
    }

    std::istringstream iss(filter_string);
    std::string token;
    
    while (std::getline(iss, token, ' ')) {
        if (token.empty()) continue;
        
        size_t eq_pos = token.find('=');
        if (eq_pos == std::string::npos) continue;
        
        std::string key = token.substr(0, eq_pos);
        std::string value = token.substr(eq_pos + 1);
        
        // Convert key to lowercase for case-insensitive matching.
        std::transform(key.begin(), key.end(), key.begin(), ::tolower);
        
        if (key == "protocol") {
            filter_.protocol = value;
        } else if (key == "src_ip") {
            filter_.src_ip = value;
        } else if (key == "dst_ip") {
            filter_.dst_ip = value;
        } else if (key == "src_port") {
            filter_.src_port = static_cast<uint16_t>(std::stoi(value));
        } else if (key == "dst_port") {
            filter_.dst_port = static_cast<uint16_t>(std::stoi(value));
        } else if (key == "src_mac") {
            filter_.src_mac = value;
        } else if (key == "dst_mac") {
            filter_.dst_mac = value;
        } else if (key == "vlan_id") {
            filter_.vlan_id = static_cast<uint16_t>(std::stoi(value));
        } else if (key == "min_size") {
            filter_.min_size = std::stoi(value);
        } else if (key == "max_size") {
            filter_.max_size = std::stoi(value);
        }
    }
    
    return true;
}

bool Stats::matchesFilter(const ParsedPacket& packet) const {
    if (!filter_.has_any_filter()) {
        return true; // No filter means match all
    }
    
    // Check MAC filters.
    if (filter_.has_mac_filter()) {
        if (!filter_.src_mac.empty() && !macMatches(packet.src_mac(), filter_.src_mac)) {
            return false;
        }
        if (!filter_.dst_mac.empty() && !macMatches(packet.dst_mac(), filter_.dst_mac)) {
            return false;
        }
    }
    
    // Check VLAN filter.
    if (filter_.has_vlan_filter()) {
        if (!packet.has_l2() || packet.l2.vlan_id != filter_.vlan_id) {
            return false;
        }
    }
    
    // Check protocol filter.
    if (filter_.has_protocol()) {
        if (!Parser::is_protocol(packet, filter_.protocol)) {
            return false;
        }
    }
    
    // Check IP filters.
    if (filter_.has_ip_filter()) {
        if (!packet.has_l3()) return false;
        
        if (!filter_.src_ip.empty() && !ipMatches(packet.src_ip(), filter_.src_ip)) {
            return false;
        }
        if (!filter_.dst_ip.empty() && !ipMatches(packet.dst_ip(), filter_.dst_ip)) {
            return false;
        }
    }
    
    // Check port filters.
    if (filter_.has_port_filter()) {
        if (!packet.has_l4()) return false;
        
        if (filter_.src_port != 0 && packet.src_port() != filter_.src_port) {
            return false;
        }
        if (filter_.dst_port != 0 && packet.dst_port() != filter_.dst_port) {
            return false;
        }
    }
    
    // Check size filters.
    if (filter_.has_size_filter()) {
        if (filter_.min_size > 0 && packet.total_length < filter_.min_size) {
            return false;
        }
        if (filter_.max_size > 0 && packet.total_length > filter_.max_size) {
            return false;
        }
    }
    
    return true;
}

FilterStats Stats::applyFilter(const std::string& filename) const {
    FilterStats stats;
    stats.filter_description = "Custom filter";
    
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return stats;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) continue;
        
        ParsedPacket packet = Parser::deserialize_packet(line);
        if (matchesFilter(packet)) {
            stats.packet_count++;
            stats.total_bytes += packet.total_length;
        }
    }
    
    return stats;
}

std::unordered_map<std::string, uint64_t> Stats::groupPackets(
    const std::string& filename, 
    GroupBy group_by
) const {
    std::unordered_map<std::string, uint64_t> groups;
    
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return groups;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) continue;
        
        ParsedPacket packet = Parser::deserialize_packet(line);
        std::string key = getGroupingKey(packet, group_by);
        groups[key]++;
    }
    
    return groups;
}

std::string Stats::getGroupingReport(
    const std::string& filename, 
    GroupBy group_by
) const {
    auto groups = groupPackets(filename, group_by);
    return formatGroupingResults(groups, group_by);
}

bool Stats::hasActiveFilter() const {
    return filter_.has_any_filter();
}

bool Stats::macMatches(const std::string& packet_mac, const std::string& filter_mac) const {
    // Simple exact match for now.
    return packet_mac == filter_mac;
}

bool Stats::ipMatches(const std::string& packet_ip, const std::string& filter_ip) const {
    // Simple exact match for now. (CIDR support can be added later).
    return packet_ip == filter_ip;
}

std::string Stats::getGroupingKey(const ParsedPacket& packet, GroupBy group_by) const {
    switch (group_by) {
        case GroupBy::SRC_MAC:
            return packet.has_l2() ? packet.src_mac() : "Unknown";
        case GroupBy::DST_MAC:
            return packet.has_l2() ? packet.dst_mac() : "Unknown";
        case GroupBy::VLAN_ID:
            return packet.has_l2() ? std::to_string(packet.l2.vlan_id) : "0";
        case GroupBy::PROTOCOL:
            if (packet.has_l4()) return packet.l4.protocol_name;
            if (packet.has_l3()) return packet.l3.protocol_name;
            if (packet.has_l2()) return packet.l2.protocol_name;
            return "Unknown";
        case GroupBy::SRC_IP:
            return packet.has_l3() ? packet.src_ip() : "Unknown";
        case GroupBy::DST_IP:
            return packet.has_l3() ? packet.dst_ip() : "Unknown";
        case GroupBy::SRC_PORT:
            return packet.has_l4() ? std::to_string(packet.src_port()) : "0";
        case GroupBy::DST_PORT:
            return packet.has_l4() ? std::to_string(packet.dst_port()) : "0";
        case GroupBy::PACKET_SIZE:
            return getSizeRange(packet.total_length);
        default:
            return "Unknown";
    }
}

std::string Stats::getSizeRange(uint32_t packet_size) const {
    if (packet_size < 64) return "0-63";
    if (packet_size < 128) return "64-127";
    if (packet_size < 256) return "128-255";
    if (packet_size < 512) return "256-511";
    if (packet_size < 1024) return "512-1023";
    if (packet_size < 1500) return "1024-1499";
    return "1500+";
}

std::string Stats::formatGroupingResults(
    const std::unordered_map<std::string, uint64_t>& groups, 
    GroupBy group_by
) const {
    std::ostringstream oss;
    
    // Get group name for header.
    std::string group_name;
    switch (group_by) {
        case GroupBy::SRC_MAC: group_name = "Source MAC"; break;
        case GroupBy::DST_MAC: group_name = "Destination MAC"; break;
        case GroupBy::VLAN_ID: group_name = "VLAN ID"; break;
        case GroupBy::PROTOCOL: group_name = "Protocol"; break;
        case GroupBy::SRC_IP: group_name = "Source IP"; break;
        case GroupBy::DST_IP: group_name = "Destination IP"; break;
        case GroupBy::SRC_PORT: group_name = "Source Port"; break;
        case GroupBy::DST_PORT: group_name = "Destination Port"; break;
        case GroupBy::PACKET_SIZE: group_name = "Packet Size"; break;
        default: group_name = "Unknown"; break;
    }
    
    oss << "\n=== Grouping by " << group_name << " ===" << std::endl;
    
    // Sort by count (descending).
    std::vector<std::pair<std::string, uint64_t>> sorted_groups(groups.begin(), groups.end());
    std::sort(sorted_groups.begin(), sorted_groups.end(), 
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    for (const auto& group : sorted_groups) {
        oss << group.first << ": " << group.second << " packets" << std::endl;
    }
    
    return oss.str();
}
