#include "sniff_recvfrom.h"
#include "capture_tpv3.h"
#include "parse.h"
#include <iostream>
#include <iomanip>
#include <string>

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " <command> [options]" << std::endl;
    std::cout << std::endl;
    std::cout << "Commands:" << std::endl;
    std::cout << "  sniff --in <interface>   Sniff packets using recvfrom()" << std::endl;
    std::cout << "  sniff3 --in <interface> Sniff packets using TPACKET_V3 (high performance)" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << program_name << " sniff --in eth0" << std::endl;
    std::cout << "  " << program_name << " sniff3 --in veth1" << std::endl;
    std::cout << std::endl;
    std::cout << "Note: This program requires CAP_NET_RAW capability or sudo privileges." << std::endl;
}

// Callback function for TPACKET_V3 packet processing
void on_packet_frame(const uint8_t* frame, uint32_t len) {
    // Parse and print packet summary
    Parsed parsed;
    int parse_result = parse_frame(frame, len, &parsed);
    
    if (parse_result == 0) {
        // Successfully parsed - print structured output
        parsed_print(&parsed);
    } else {
        // Parse failed - fall back to hex output
        std::cout << "Length: " << std::setw(4) << len << " | ";
        std::cout << "Data: ";
        
        // Print first 14 bytes (Ethernet header) in hex
        int bytes_to_print = std::min(static_cast<int>(len), 14);
        for (int i = 0; i < bytes_to_print; ++i) {
            std::cout << std::hex << std::setfill('0') << std::setw(2) 
                      << (static_cast<unsigned char>(frame[i]) & 0xFF) << " ";
        }
        std::cout << std::dec << " (parse error: " << parse_result << ")" << std::endl;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string command = argv[1];

    if (command == "sniff") {
        if (argc < 4 || std::string(argv[2]) != "--in") {
            std::cerr << "Error: sniff command requires --in <interface> argument." << std::endl;
            print_usage(argv[0]);
            return 1;
        }

        std::string interface_name = argv[3];
        return sniff_packets(interface_name);
    } else if (command == "sniff3") {
        if (argc < 4 || std::string(argv[2]) != "--in") {
            std::cerr << "Error: sniff3 command requires --in <interface> argument." << std::endl;
            print_usage(argv[0]);
            return 1;
        }

        std::string interface_name = argv[3];
        
        // Open TPACKET_V3 capture
        if (tpv3_open(interface_name.c_str()) < 0) {
            return 1;
        }

        std::cout << "Press Ctrl+C to stop..." << std::endl;

        // Main capture loop
        while (true) {
            // Poll for packets (1 second timeout)
            int ret = tpv3_poll(1000);
            if (ret < 0) {
                std::cerr << "Error: poll() failed" << std::endl;
                break;
            } else if (ret > 0) {
                // Process available packets
                int packets = tpv3_next(on_packet_frame);
                if (packets < 0) {
                    std::cerr << "Error: failed to process packets" << std::endl;
                    break;
                }
            }
            // If ret == 0, timeout occurred, continue polling
        }

        tpv3_close();
        return 0;
    } else if (command == "--help" || command == "-h") {
        print_usage(argv[0]);
        return 0;
    } else {
        std::cerr << "Error: Unknown command '" << command << "'." << std::endl;
        print_usage(argv[0]);
        return 1;
    }
}
