#ifndef TCP_FLOW_ANALYZER_H
#define TCP_FLOW_ANALYZER_H

#include "parser.h"
#include <string>
#include <unordered_map>
#include <vector>
#include <set>
#include <stdint.h>


/*
* TCP flow analyzer is a static class that is used to analyze TCP flows in a capture file.
* Provides methods to analyze the flows and generate a report.
*/

struct TCPFlow {
    std::string flow_id;
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    
    uint32_t packets_sent;
    uint32_t packets_received;
    uint32_t bytes_sent;
    uint32_t bytes_received;
    
    uint32_t syn_packets;
    uint32_t syn_ack_packets;
    uint32_t ack_packets;
    uint32_t fin_packets;
    uint32_t rst_packets;
    uint32_t retransmissions;
    
    bool connection_established;
    bool connection_closed;
    uint32_t max_window_size;
    uint32_t min_window_size;
    
    uint64_t first_packet_time;
    uint64_t last_packet_time;
    
    std::set<uint32_t> seen_sequence_numbers;
    
    TCPFlow() : src_port(0), dst_port(0), packets_sent(0), packets_received(0),
                bytes_sent(0), bytes_received(0), syn_packets(0), syn_ack_packets(0),
                ack_packets(0), fin_packets(0), rst_packets(0), retransmissions(0),
                connection_established(false), connection_closed(false),
                max_window_size(0), min_window_size(0), first_packet_time(0), last_packet_time(0) {}
};

struct TCPFlowAnalysis {
    std::unordered_map<std::string, TCPFlow> flows;
    std::vector<std::string> flow_ids;
    uint32_t total_flows;
    uint32_t established_flows;
    uint32_t closed_flows;
    uint32_t total_tcp_packets;
    uint32_t total_retransmissions;
    
    TCPFlowAnalysis() : total_flows(0), established_flows(0), closed_flows(0),
                       total_tcp_packets(0), total_retransmissions(0) {}
};

class TCPFlowAnalyzer {
public:
    // Reads a capture file and returns an object containing all of the flows and related information.
    static TCPFlowAnalysis analyzeFlows(const std::string& filename);
    // Generates a string of information relating to all of the flows in a file.
    static std::string generateFlowReport(const TCPFlowAnalysis& analysis);
    // Used to iterate through the flows analyzed in a capture file.
    static std::pair<std::string, TCPFlow> getCurrentFlow(const TCPFlowAnalysis& analysis, size_t current_index);
    static std::pair<std::string, TCPFlow> getNextFlow(const TCPFlowAnalysis& analysis, size_t current_index);
    static std::pair<std::string, TCPFlow> getPrevFlow(const TCPFlowAnalysis& analysis, size_t current_index);
    // Returns the number of flows analyzed in a capture file.
    static size_t getFlowCount(const TCPFlowAnalysis& analysis);
    
private:
    static std::string generateFlowId(const ParsedPacket& packet);
    static std::string generateReverseFlowId(const ParsedPacket& packet);
    static bool isRetransmission(const ParsedPacket& packet, const TCPFlow& flow);
    static void updateFlow(TCPFlow& flow, const ParsedPacket& packet, bool is_reverse);
};

#endif