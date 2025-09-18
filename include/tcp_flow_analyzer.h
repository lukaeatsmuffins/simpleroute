#pragma once

#include "parser.h"
#include <string>
#include <unordered_map>
#include <vector>
#include <stdint.h>

// TCP Flow Analysis - Dedicated class for analyzing TCP connections and flows

// TCP Flow information structure
struct TCPFlow {
    std::string flow_id;               // "src_ip:src_port->dst_ip:dst_port"
    std::string src_ip;               // Source IP address
    std::string dst_ip;               // Destination IP address
    uint16_t src_port;                // Source port
    uint16_t dst_port;                // Destination port
    
    // Packet counts
    uint32_t packets_sent;            // Packets from src to dst
    uint32_t packets_received;        // Packets from dst to src
    uint32_t bytes_sent;              // Bytes from src to dst
    uint32_t bytes_received;          // Bytes from dst to src
    
    // TCP-specific metrics
    uint32_t syn_packets;             // SYN packets
    uint32_t syn_ack_packets;         // SYN-ACK packets
    uint32_t ack_packets;             // ACK packets
    uint32_t fin_packets;             // FIN packets
    uint32_t rst_packets;             // RST packets
    uint32_t retransmissions;         // Detected retransmissions
    
    // Connection state tracking
    bool connection_established;      // SYN-ACK received
    bool connection_closed;           // FIN or RST received
    uint32_t max_window_size;        // Maximum window size observed
    uint32_t min_window_size;         // Minimum window size observed
    
    // Timing information (if available)
    uint64_t first_packet_time;       // Timestamp of first packet
    uint64_t last_packet_time;        // Timestamp of last packet
    
    // Constructor
    TCPFlow() : src_port(0), dst_port(0), packets_sent(0), packets_received(0),
                bytes_sent(0), bytes_received(0), syn_packets(0), syn_ack_packets(0),
                ack_packets(0), fin_packets(0), rst_packets(0), retransmissions(0),
                connection_established(false), connection_closed(false),
                max_window_size(0), min_window_size(0), first_packet_time(0), last_packet_time(0) {}
};

// TCP Flow Analysis Results
struct TCPFlowAnalysis {
    std::unordered_map<std::string, TCPFlow> flows;  // Fast flow lookup by ID
    std::vector<std::string> flow_ids;               // Ordered flow IDs for indexing
    uint32_t total_flows;
    uint32_t established_flows;
    uint32_t closed_flows;
    uint32_t total_tcp_packets;
    uint32_t total_retransmissions;
    
    TCPFlowAnalysis() : total_flows(0), established_flows(0), closed_flows(0),
                       total_tcp_packets(0), total_retransmissions(0) {}
};

// Main TCP Flow Analyzer class
class TCPFlowAnalyzer {
public:
    // Analyze TCP flows from a capture file
    static TCPFlowAnalysis analyzeFlows(const std::string& filename);
    
    // Generate a formatted report of TCP flows
    static std::string generateFlowReport(const TCPFlowAnalysis& analysis);
    
    // Flow navigation methods
    static std::pair<std::string, TCPFlow> getCurrentFlow(const TCPFlowAnalysis& analysis, size_t current_index);
    static std::pair<std::string, TCPFlow> getNextFlow(const TCPFlowAnalysis& analysis, size_t current_index);
    static std::pair<std::string, TCPFlow> getPrevFlow(const TCPFlowAnalysis& analysis, size_t current_index);
    static size_t getFlowCount(const TCPFlowAnalysis& analysis);
    
private:
    // Generate flow ID from packet information
    static std::string generateFlowId(const ParsedPacket& packet);
    
    // Generate reverse flow ID (for bidirectional analysis)
    static std::string generateReverseFlowId(const ParsedPacket& packet);
    
    // Check if packet is a retransmission
    static bool isRetransmission(const ParsedPacket& packet, const TCPFlow& flow);
    
    // Update flow with packet information
    static void updateFlow(TCPFlow& flow, const ParsedPacket& packet, bool is_reverse);
};

