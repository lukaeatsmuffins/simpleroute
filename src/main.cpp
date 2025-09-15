#include "IOHandler.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <cstdio>

void test_iohandler(); 

int main() {
    // IOHandler& handler = IOHandler::getInstance();
    // std::cout << "IOHandler instance created" << std::endl;
   
    test_iohandler();

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