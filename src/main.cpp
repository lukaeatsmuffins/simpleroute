#include "IOHandler.h"
#include "l2_parser.h"
#include "l3_parser.h"
#include "l4_parser.h"
#include "parser.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <cstdio>
#include <vector>

void test_iohandler(); 
void test_parsers();
void test_parser_class();

int main() {
    std::cout << "=== Starting Packet Processing Pipeline ===" << std::endl;
    
    // Initialize IOHandler singleton
    IOHandler& handler = IOHandler::getInstance();
    
    // Configure buffer size for packet storage
    bool buffer_set = handler.setBufferSize(1000);
    if (!buffer_set) {
        std::cerr << "Failed to set buffer size!" << std::endl;
        return 1;
    }
    std::cout << "Buffer size configured successfully" << std::endl;
    
    // Start packet capture on lo interface (loopback)
    std::cout << "Starting packet capture on lo (loopback)..." << std::endl;
    bool capture_started = handler.startCapture("lo");
    if (!capture_started) {
        std::cerr << "Failed to start packet capture!" << std::endl;
        return 1;
    }
    std::cout << "Packet capture started successfully!" << std::endl;
    
    // Main consumer loop - parse and display packets
    std::cout << "\n=== Packet Processing Pipeline Active ===" << std::endl;
    std::cout << "Monitoring packets for 30 seconds..." << std::endl;
    
    int packet_count = 0;
    auto start_time = std::chrono::steady_clock::now();
    auto end_time = start_time + std::chrono::seconds(30);
    
    while (std::chrono::steady_clock::now() < end_time) {
        std::vector<uint8_t> packet;
        
        // Wait for packet data to be available
        handler.waitForData();
        
        // Read packet from buffer
        if (handler.readPacket(packet)) {
            packet_count++;
            
            // Parse the packet using our parser
            ParsedPacket parsed = Parser::parse_packet(packet, 0);
            
            // Display basic packet information
            std::cout << "\n--- Packet #" << packet_count << " ---" << std::endl;
            std::cout << "Size: " << packet.size() << " bytes" << std::endl;
            std::cout << "Summary: " << Parser::get_summary(parsed) << std::endl;
            std::cout << "Flow: " << Parser::get_flow_id(parsed) << std::endl;
            std::cout << "Protocol Stack: " << Parser::get_protocol_stack(parsed) << std::endl;
            
            // Show detailed info for first few packets
            if (packet_count <= 3) {
                std::cout << Parser::get_details(parsed) << std::endl;
            }
        }
    }
    
    // Stop capture and cleanup
    std::cout << "\n=== Stopping Packet Capture ===" << std::endl;
    handler.stopCapture();
    std::cout << "Processed " << packet_count << " packets in 30 seconds" << std::endl;
    std::cout << "Pipeline test completed successfully!" << std::endl;
    
    return 0;
}

void test_iohandler() {
    IOHandler& handler = IOHandler::getInstance();
    
    std::cout << "Testing IOHandler with real network interface..." << std::endl;
    
    // Test 1: Check initial state
    std::cout << "1. Initial state - isCapturing: " << (handler.isCapturing() ? "true" : "false") << std::endl;
    
    // Test 2: Set buffer size
    bool buffer_set = handler.setBufferSize(100);
    std::cout << "2. Set buffer size to 100: " << (buffer_set ? "success" : "failed") << std::endl;
    
    // Test 3: Start capture on eth0
    std::cout << "3. Starting capture on eth0..." << std::endl;
    bool capture_started = handler.startCapture("eth0");
    std::cout << "   Start capture result: " << (capture_started ? "success" : "failed") << std::endl;
    
    if (capture_started) {
        std::cout << "4. Capture started successfully! Checking for packets..." << std::endl;
        
        // Test 4: Check for packets over a few seconds
        int attempts = 0;
        int packets_found = 0;
        std::vector<uint8_t> packet;
        
        std::cout << "   Monitoring for 10 seconds..." << std::endl;
        for (int i = 0; i < 100; ++i) {  // 10 seconds total
            attempts++;
            if (handler.readPacket(packet)) {
                packets_found++;
                std::cout << "   Packet " << packets_found << ": " << packet.size() << " bytes" << std::endl;
                
                // Show first few bytes of packet
                std::cout << "     First 16 bytes: ";
                for (size_t j = 0; j < std::min(packet.size(), size_t(16)); ++j) {
                    printf("%02x ", packet[j]);
                }
                std::cout << std::endl;
                
                if (packets_found >= 5) {  // Stop after capturing 5 packets
                    std::cout << "   Captured enough packets for demonstration." << std::endl;
                    break;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        std::cout << "5. Monitoring complete - found " << packets_found << " packets in " << attempts << " attempts" << std::endl;
    }
    
    // Test 5: Stop capture
    handler.stopCapture();
    std::cout << "6. After stopCapture - isCapturing: " << (handler.isCapturing() ? "true" : "false") << std::endl;
    
    std::cout << "IOHandler test completed." << std::endl;
}

void test_parsers() {
    // Create a sample Ethernet + IPv4 + TCP packet
    std::vector<uint8_t> test_packet = {
        // Ethernet header (14 bytes)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // Destination MAC
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,  // Source MAC
        0x08, 0x00,                            // EtherType: IPv4
        
        // IPv4 header (20 bytes)
        0x45,                                  // Version(4) + IHL(5)
        0x00,                                  // Type of Service
        0x00, 0x3C,                            // Total Length (60 bytes)
        0x12, 0x34,                            // Identification
        0x40, 0x00,                            // Flags + Fragment Offset (Don't Fragment)
        0x40,                                  // TTL (64)
        0x06,                                  // Protocol (TCP)
        0x00, 0x00,                            // Header Checksum (placeholder)
        0xC0, 0xA8, 0x01, 0x64,                // Source IP: 192.168.1.100
        0xC0, 0xA8, 0x01, 0x01,                // Dest IP: 192.168.1.1
        
        // TCP header (20 bytes)
        0x04, 0xD2,                            // Source Port: 1234
        0x00, 0x50,                            // Dest Port: 80 (HTTP)
        0x00, 0x00, 0x00, 0x01,                // Sequence Number
        0x00, 0x00, 0x00, 0x00,                // Acknowledgment Number
        0x50,                                  // Data Offset (5) + Reserved
        0x02,                                  // Flags: SYN
        0x20, 0x00,                            // Window Size
        0x00, 0x00,                            // Checksum (placeholder)
        0x00, 0x00,                            // Urgent Pointer
        
        // Some payload data
        0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21     // "Hello!"
    };
    
    std::cout << "Testing with sample Ethernet + IPv4 + TCP packet (" 
              << test_packet.size() << " bytes)\n" << std::endl;
    
    // Test L2 Parser
    std::cout << "1. L2 Parser Test:" << std::endl;
    L2Info l2_result = L2Parser::parse(test_packet, 0);
    std::cout << "   Parsed: " << (l2_result.parsed ? "Yes" : "No") << std::endl;
    std::cout << "   Result: " << l2_result.info_string << std::endl;
    std::cout << "   Source MAC: " << l2_result.src_mac << std::endl;
    std::cout << "   Dest MAC: " << l2_result.dst_mac << std::endl;
    std::cout << "   EtherType: 0x" << std::hex << l2_result.ether_type << std::dec << std::endl;
    std::cout << "   Protocol: " << l2_result.protocol_name << std::endl;
    std::cout << "   Next layer offset: " << l2_result.next_layer_offset << std::endl;
    
    // Test L3 Parser
    std::cout << "\n2. L3 Parser Test:" << std::endl;
    L3Info l3_result = L3Parser::parse(test_packet, l2_result.next_layer_offset);
    std::cout << "   Parsed: " << (l3_result.parsed ? "Yes" : "No") << std::endl;
    std::cout << "   Result: " << l3_result.info_string << std::endl;
    std::cout << "   Source IP: " << l3_result.src_ip << std::endl;
    std::cout << "   Dest IP: " << l3_result.dst_ip << std::endl;
    std::cout << "   Protocol: " << l3_result.protocol_name << std::endl;
    std::cout << "   TTL: " << static_cast<int>(l3_result.ttl) << std::endl;
    std::cout << "   Fragmented: " << (l3_result.is_fragmented ? "Yes" : "No") << std::endl;
    std::cout << "   Next layer offset: " << l3_result.next_layer_offset << std::endl;
    
    // Test L4 Parser
    std::cout << "\n3. L4 Parser Test:" << std::endl;
    L4Info l4_result = L4Parser::parse(test_packet, l3_result.next_layer_offset, l3_result.next_protocol);
    std::cout << "   Parsed: " << (l4_result.parsed ? "Yes" : "No") << std::endl;
    std::cout << "   Result: " << l4_result.info_string << std::endl;
    std::cout << "   Source Port: " << l4_result.src_port << " (" << l4_result.src_service << ")" << std::endl;
    std::cout << "   Dest Port: " << l4_result.dst_port << " (" << l4_result.dst_service << ")" << std::endl;
    std::cout << "   TCP Flags: " << l4_result.tcp_flags_string << std::endl;
    std::cout << "   Sequence: " << l4_result.sequence_number << std::endl;
    std::cout << "   Window: " << l4_result.window_size << std::endl;
    std::cout << "   Next layer offset: " << l4_result.next_layer_offset << std::endl;
    
    // Test with VLAN packet
    std::cout << "\n--- Testing VLAN packet ---" << std::endl;
    std::vector<uint8_t> vlan_packet = {
        // Ethernet header with VLAN
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // Destination MAC
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,  // Source MAC
        0x81, 0x00,                            // EtherType: VLAN
        0x00, 0x64,                            // VLAN TCI (VLAN ID = 100)
        0x08, 0x00,                            // Inner EtherType: IPv4
        
        // IPv4 header (simplified)
        0x45, 0x00, 0x00, 0x1C,                // Version, IHL, ToS, Length
        0x00, 0x00, 0x40, 0x00,                // ID, Flags, Frag
        0x40, 0x11, 0x00, 0x00,                // TTL, Protocol(UDP), Checksum
        0x0A, 0x00, 0x00, 0x01,                // Source IP: 10.0.0.1
        0x0A, 0x00, 0x00, 0x02,                // Dest IP: 10.0.0.2
        
        // UDP header
        0x00, 0x35,                            // Source Port: 53 (DNS)
        0x00, 0x35,                            // Dest Port: 53 (DNS)
        0x00, 0x08,                            // Length: 8
        0x00, 0x00                             // Checksum
    };
    
    std::cout << "4. L2 Parser (VLAN) Test:" << std::endl;
    L2Info vlan_l2_result = L2Parser::parse(vlan_packet, 0);
    std::cout << "   Parsed: " << (vlan_l2_result.parsed ? "Yes" : "No") << std::endl;
    std::cout << "   Result: " << vlan_l2_result.info_string << std::endl;
    std::cout << "   Has VLAN: " << (vlan_l2_result.has_vlan ? "Yes" : "No") << std::endl;
    std::cout << "   VLAN ID: " << vlan_l2_result.vlan_id << std::endl;
    std::cout << "   VLAN Priority: " << static_cast<int>(vlan_l2_result.vlan_priority) << std::endl;
    
    std::cout << "\n5. L3 Parser (from VLAN packet) Test:" << std::endl;
    L3Info vlan_l3_result = L3Parser::parse(vlan_packet, vlan_l2_result.next_layer_offset);
    std::cout << "   Parsed: " << (vlan_l3_result.parsed ? "Yes" : "No") << std::endl;
    std::cout << "   Result: " << vlan_l3_result.info_string << std::endl;
    std::cout << "   Source IP: " << vlan_l3_result.src_ip << std::endl;
    std::cout << "   Dest IP: " << vlan_l3_result.dst_ip << std::endl;
    
    std::cout << "\n6. L4 Parser (UDP) Test:" << std::endl;
    L4Info udp_result = L4Parser::parse(vlan_packet, vlan_l3_result.next_layer_offset, vlan_l3_result.next_protocol);
    std::cout << "   Parsed: " << (udp_result.parsed ? "Yes" : "No") << std::endl;
    std::cout << "   Result: " << udp_result.info_string << std::endl;
    std::cout << "   Source Port: " << udp_result.src_port << " (" << udp_result.src_service << ")" << std::endl;
    std::cout << "   Dest Port: " << udp_result.dst_port << " (" << udp_result.dst_service << ")" << std::endl;
    std::cout << "   UDP Length: " << udp_result.udp_length << std::endl;
    
    // Test ICMP
    std::cout << "\n--- Testing ICMP packet ---" << std::endl;
    std::vector<uint8_t> icmp_packet = {
        // Ethernet header
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // Destination MAC
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,  // Source MAC
        0x08, 0x00,                            // EtherType: IPv4
        
        // IPv4 header
        0x45, 0x00, 0x00, 0x1C,                // Version, IHL, ToS, Length
        0x00, 0x00, 0x40, 0x00,                // ID, Flags, Frag
        0x40, 0x01, 0x00, 0x00,                // TTL, Protocol(ICMP), Checksum
        0xC0, 0xA8, 0x01, 0x01,                // Source IP: 192.168.1.1
        0xC0, 0xA8, 0x01, 0x02,                // Dest IP: 192.168.1.2
        
        // ICMP header
        0x08,                                  // Type: Echo Request
        0x00,                                  // Code: 0
        0x00, 0x00,                            // Checksum
        0x12, 0x34,                            // Identifier
        0x00, 0x01                             // Sequence Number
    };
    
    std::cout << "7. L4 Parser (ICMP) Test:" << std::endl;
    L4Info icmp_result = L4Parser::parse(icmp_packet, 34, L4Parser::PROTO_ICMP);
    std::cout << "   Parsed: " << (icmp_result.parsed ? "Yes" : "No") << std::endl;
    std::cout << "   Result: " << icmp_result.info_string << std::endl;
    std::cout << "   ICMP Type: " << static_cast<int>(icmp_result.icmp_type) << std::endl;
    std::cout << "   ICMP Code: " << static_cast<int>(icmp_result.icmp_code) << std::endl;
    std::cout << "   Protocol: " << icmp_result.protocol_name << std::endl;
    
    std::cout << "\nParser tests completed!" << std::endl;
}

void test_parser_class() {
    // Create a sample Ethernet + IPv4 + TCP packet
    std::vector<uint8_t> test_packet = {
        // Ethernet header (14 bytes)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // Destination MAC
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,  // Source MAC
        0x08, 0x00,                            // EtherType: IPv4
        
        // IPv4 header (20 bytes)
        0x45,                                  // Version(4) + IHL(5)
        0x00,                                  // Type of Service
        0x00, 0x3C,                            // Total Length (60 bytes)
        0x12, 0x34,                            // Identification
        0x40, 0x00,                            // Flags + Fragment Offset (Don't Fragment)
        0x40,                                  // TTL (64)
        0x06,                                  // Protocol (TCP)
        0x00, 0x00,                            // Header Checksum (placeholder)
        0xC0, 0xA8, 0x01, 0x64,                // Source IP: 192.168.1.100
        0xC0, 0xA8, 0x01, 0x01,                // Dest IP: 192.168.1.1
        
        // TCP header (20 bytes)
        0x04, 0xD2,                            // Source Port: 1234
        0x00, 0x50,                            // Dest Port: 80 (HTTP)
        0x00, 0x00, 0x00, 0x01,                // Sequence Number
        0x00, 0x00, 0x00, 0x00,                // Acknowledgment Number
        0x50,                                  // Data Offset (5) + Reserved
        0x02,                                  // Flags: SYN
        0x20, 0x00,                            // Window Size
        0x00, 0x00,                            // Checksum (placeholder)
        0x00, 0x00,                            // Urgent Pointer
        
        // Some payload data
        0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21     // "Hello!"
    };
    
    std::cout << "Testing Parser class with sample packet (" << test_packet.size() << " bytes)\n" << std::endl;
    
    // Parse the complete packet
    ParsedPacket parsed = Parser::parse_packet(test_packet, 0);
    
    // Test summary
    std::cout << "1. Packet Summary:" << std::endl;
    std::cout << "   " << Parser::get_summary(parsed) << std::endl;
    
    // Test protocol stack
    std::cout << "\n2. Protocol Stack:" << std::endl;
    std::cout << "   " << Parser::get_protocol_stack(parsed) << std::endl;
    
    // Test flow ID
    std::cout << "\n3. Flow ID:" << std::endl;
    std::cout << "   " << Parser::get_flow_id(parsed) << std::endl;
    
    // Test protocol detection
    std::cout << "\n4. Protocol Detection:" << std::endl;
    std::cout << "   Is TCP: " << (Parser::is_protocol(parsed, "TCP") ? "Yes" : "No") << std::endl;
    std::cout << "   Is IPv4: " << (Parser::is_protocol(parsed, "IPv4") ? "Yes" : "No") << std::endl;
    std::cout << "   Is UDP: " << (Parser::is_protocol(parsed, "UDP") ? "Yes" : "No") << std::endl;
    std::cout << "   Is Ethernet: " << (Parser::is_protocol(parsed, "Ethernet") ? "Yes" : "No") << std::endl;
    
    // Test header overhead
    std::cout << "\n5. Header Analysis:" << std::endl;
    std::cout << "   Header Overhead: " << Parser::get_header_overhead(parsed) << " bytes" << std::endl;
    std::cout << "   Has Payload: " << (Parser::has_payload(parsed) ? "Yes" : "No") << std::endl;
    std::cout << "   Payload Length: " << parsed.payload_length << " bytes" << std::endl;
    
    // Test detailed information
    std::cout << "\n6. Detailed Information:" << std::endl;
    std::cout << Parser::get_details(parsed) << std::endl;
    
    // Test VLAN packet
    std::cout << "\n--- Testing VLAN packet with Parser class ---" << std::endl;
    std::vector<uint8_t> vlan_packet = {
        // Ethernet header with VLAN
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // Destination MAC
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,  // Source MAC
        0x81, 0x00,                            // EtherType: VLAN
        0x00, 0x64,                            // VLAN TCI (VLAN ID = 100)
        0x08, 0x00,                            // Inner EtherType: IPv4
        
        // IPv4 header (simplified)
        0x45, 0x00, 0x00, 0x1C,                // Version, IHL, ToS, Length
        0x00, 0x00, 0x40, 0x00,                // ID, Flags, Frag
        0x40, 0x11, 0x00, 0x00,                // TTL, Protocol(UDP), Checksum
        0x0A, 0x00, 0x00, 0x01,                // Source IP: 10.0.0.1
        0x0A, 0x00, 0x00, 0x02,                // Dest IP: 10.0.0.2
        
        // UDP header
        0x00, 0x35,                            // Source Port: 53 (DNS)
        0x00, 0x35,                            // Dest Port: 53 (DNS)
        0x00, 0x08,                            // Length: 8
        0x00, 0x00                             // Checksum
    };
    
    ParsedPacket vlan_parsed = Parser::parse_packet(vlan_packet, 0);
    
    std::cout << "7. VLAN Packet Summary:" << std::endl;
    std::cout << "   " << Parser::get_summary(vlan_parsed) << std::endl;
    std::cout << "   Protocol Stack: " << Parser::get_protocol_stack(vlan_parsed) << std::endl;
    std::cout << "   Flow ID: " << Parser::get_flow_id(vlan_parsed) << std::endl;
    std::cout << "   Has VLAN: " << (Parser::is_protocol(vlan_parsed, "VLAN") ? "Yes" : "No") << std::endl;
    
    std::cout << "\nParser class tests completed!" << std::endl;
}