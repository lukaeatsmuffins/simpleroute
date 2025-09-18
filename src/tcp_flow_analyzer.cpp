#include "tcp_flow_analyzer.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iostream>
#include <iomanip>

TCPFlowAnalysis TCPFlowAnalyzer::analyzeFlows(const std::string& filename) {
    TCPFlowAnalysis analysis;
    
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return analysis;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) continue;
        
        ParsedPacket packet = Parser::deserialize_packet(line);
        
        // Skip non-TCP packets.
        if (!packet.has_l4() || packet.l4.protocol_type != L4Parser::PROTO_TCP) {
            continue;
        }
        
        analysis.total_tcp_packets++;
        
        std::string flow_id = generateFlowId(packet);
        std::string reverse_flow_id = generateReverseFlowId(packet);
        
        // Check if this is a reverse flow.
        bool is_reverse = false;
        TCPFlow* flow = nullptr;
        
        auto forward_it = analysis.flows.find(flow_id);
        auto reverse_it = analysis.flows.find(reverse_flow_id);
        
        if (forward_it != analysis.flows.end()) {
            flow = &forward_it->second;
        } else if (reverse_it != analysis.flows.end()) {
            flow = &reverse_it->second;
            is_reverse = true;
            flow_id = reverse_flow_id;
        }
        
        // If we found no flow, then we must create it an initialize it.
        if (!flow) {
            analysis.flows[flow_id] = TCPFlow{};
            analysis.flow_ids.push_back(flow_id);
            flow = &analysis.flows[flow_id];
            
            // Initialize the new flow.
            flow->flow_id = flow_id;
            flow->src_ip = packet.src_ip();
            flow->dst_ip = packet.dst_ip();
            flow->src_port = packet.src_port();
            flow->dst_port = packet.dst_port();
            analysis.total_flows++;
        }
        
        updateFlow(*flow, packet, is_reverse);
    }
    
    // Calculate summary statistics.
    for (auto& [flow_id, flow] : analysis.flows) {
        if (flow.connection_established) {
            analysis.established_flows++;
        }
        if (flow.connection_closed) {
            analysis.closed_flows++;
        }
        analysis.total_retransmissions += flow.retransmissions;
    }
    
    return analysis;
}

std::string TCPFlowAnalyzer::generateFlowReport(const TCPFlowAnalysis& analysis) {
    std::ostringstream oss;
    
    oss << "=== TCP Flow Analysis Report ===" << std::endl;
    oss << "Total TCP Flows: " << analysis.total_flows << std::endl;
    oss << "Established Flows: " << analysis.established_flows << std::endl;
    oss << "Closed Flows: " << analysis.closed_flows << std::endl;
    oss << "Total TCP Packets: " << analysis.total_tcp_packets << std::endl;
    oss << "Total Retransmissions: " << analysis.total_retransmissions << std::endl;
    oss << std::endl;
    oss << "Use interactive browsing to explore individual flows." << std::endl;
    
    return oss.str();
}


std::string TCPFlowAnalyzer::generateFlowId(const ParsedPacket& packet) {
    std::ostringstream oss;
    oss << packet.src_ip() << ":" << packet.src_port() 
        << "->" << packet.dst_ip() << ":" << packet.dst_port();
    return oss.str();
}

std::string TCPFlowAnalyzer::generateReverseFlowId(const ParsedPacket& packet) {
    std::ostringstream oss;
    oss << packet.dst_ip() << ":" << packet.dst_port() 
        << "->" << packet.src_ip() << ":" << packet.src_port();
    return oss.str();
}

bool TCPFlowAnalyzer::isRetransmission(const ParsedPacket& packet, const TCPFlow& flow) {
    if (packet.l4.sequence_number == 0) {
        return false;
    }
    return flow.seen_sequence_numbers.find(packet.l4.sequence_number) != flow.seen_sequence_numbers.end();
}

void TCPFlowAnalyzer::updateFlow(TCPFlow& flow, const ParsedPacket& packet, bool is_reverse) {
    // Update packet counts
    if (is_reverse) {
        flow.packets_received++;
        flow.bytes_received += packet.total_length;
    } else {
        flow.packets_sent++;
        flow.bytes_sent += packet.total_length;
    }
    
    // Update TCP flag counts
    std::string flags = packet.tcp_flags();
    if (flags.find('S') != std::string::npos) {
        flow.syn_packets++;
        if (flags.find('A') != std::string::npos) {
            flow.syn_ack_packets++;
            flow.connection_established = true;
        }
    } else if (flags.find('A') != std::string::npos) {
        flow.ack_packets++;
    }
    if (flags.find('F') != std::string::npos) {
        flow.fin_packets++;
        flow.connection_closed = true;
    }
    if (flags.find('R') != std::string::npos) {
        flow.rst_packets++;
        flow.connection_closed = true;
    }
    
    // Update window size tracking.
    if (packet.l4.window_size > 0) {
        if (flow.max_window_size == 0 || packet.l4.window_size > flow.max_window_size) {
            flow.max_window_size = packet.l4.window_size;
        }
        if (flow.min_window_size == 0 || packet.l4.window_size < flow.min_window_size) {
            flow.min_window_size = packet.l4.window_size;
        }
    }
    
    // Check for retransmissions first.
    if (isRetransmission(packet, flow)) {
        flow.retransmissions++;
    }
    
    if (packet.l4.sequence_number > 0) {
        flow.seen_sequence_numbers.insert(packet.l4.sequence_number);
    }
}

std::pair<std::string, TCPFlow> TCPFlowAnalyzer::getCurrentFlow(const TCPFlowAnalysis& analysis, size_t current_index) {
    if (current_index >= analysis.flow_ids.size()) {
        return {"", TCPFlow{}};
    }
    
    const std::string& flow_id = analysis.flow_ids[current_index];
    auto it = analysis.flows.find(flow_id);
    if (it != analysis.flows.end()) {
        return {flow_id, it->second};
    }
    
    return {"", TCPFlow{}};
}

std::pair<std::string, TCPFlow> TCPFlowAnalyzer::getNextFlow(const TCPFlowAnalysis& analysis, size_t current_index) {
    size_t next_index = current_index + 1;
    if (next_index >= analysis.flow_ids.size()) {
        return {"", TCPFlow{}};
    }
    
    const std::string& flow_id = analysis.flow_ids[next_index];
    auto it = analysis.flows.find(flow_id);
    if (it != analysis.flows.end()) {
        return {flow_id, it->second};
    }
    
    return {"", TCPFlow{}};
}

std::pair<std::string, TCPFlow> TCPFlowAnalyzer::getPrevFlow(const TCPFlowAnalysis& analysis, size_t current_index) {
    if (current_index == 0) {
        return {"", TCPFlow{}};
    }
    
    size_t prev_index = current_index - 1;
    const std::string& flow_id = analysis.flow_ids[prev_index];
    auto it = analysis.flows.find(flow_id);
    if (it != analysis.flows.end()) {
        return {flow_id, it->second};
    }
    
    return {"", TCPFlow{}};
}

size_t TCPFlowAnalyzer::getFlowCount(const TCPFlowAnalysis& analysis) {
    return analysis.flow_ids.size();
}

