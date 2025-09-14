#include "sniff_recvfrom.h"
#include "capture_tpv3.h"
#include "parse.h"
#include "action.h"
#include "tx_raw.h"
#include <arpa/inet.h>
#include <iostream>
#include <iomanip>
#include <string>

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " <command> [options]" << std::endl;
    std::cout << std::endl;
    std::cout << "Commands:" << std::endl;
    std::cout << "  sniff --in <interface>   Sniff packets using recvfrom()" << std::endl;
    std::cout << "  sniff3 --in <interface> [--rule <rule>] Sniff packets using TPACKET_V3" << std::endl;
    std::cout << "  forward --in <iface_in> --out <iface_out> [--rule <rule>] Forward packets between interfaces" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  --rule <rule>           Rule for packet processing" << std::endl;
    std::cout << "                         Format: proto=<proto>,dport=<port>,action=<action>" << std::endl;
    std::cout << "                         Example: proto=udp,dport=53,action=DROP" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << program_name << " sniff --in eth0" << std::endl;
    std::cout << "  " << program_name << " sniff3 --in veth1" << std::endl;
    std::cout << "  " << program_name << " sniff3 --in eth0 --rule 'proto=tcp,action=PRINT'" << std::endl;
    std::cout << "  " << program_name << " sniff3 --in eth0 --rule 'proto=udp,dport=53,action=DROP'" << std::endl;
    std::cout << "  " << program_name << " forward --in veth1 --out veth2" << std::endl;
    std::cout << "  " << program_name << " forward --in eth0 --out eth1 --rule 'proto=tcp,action=FORWARD'" << std::endl;
    std::cout << std::endl;
    std::cout << "Note: This program requires CAP_NET_RAW capability or sudo privileges." << std::endl;
    std::cout << "WARNING: Forward mode is for controlled demos only (e.g., veth pairs)." << std::endl;
    std::cout << "         Do not use on production networks without proper safeguards." << std::endl;
}

// Global rule for packet processing
static Rule g_rule = {PROTO_ANY, PROTO_ANY, 0, false, ACTION_PRINT};
static bool g_forward_mode = false;


// Callback function for TPACKET_V3 packet processing
void on_packet_frame(const uint8_t* frame, uint32_t len) {
    // Parse packet
    Parsed parsed;
    int parse_result = parse_frame(frame, len, &parsed);
    
    if (parse_result == 0) {
        // Successfully parsed - decide action based on rule
        ActionType action = decide(&g_rule, &parsed);
        
        if (action == ACTION_DROP) {
            // Print decision line and drop packet
            std::cout << "DECISION: DROP - ";
            parsed_print(&parsed);
            return;  // Drop packet (do nothing else)
        } else if (action == ACTION_PRINT) {
            // Print packet details
            parsed_print(&parsed);
        } else if (action == ACTION_FORWARD) {
            // Print decision line and forward packet
            std::cout << "DECISION: FORWARD - ";
            parsed_print(&parsed);
            
            if (g_forward_mode) {
                int tx_result = tx_send(frame, len);
                if (tx_result < 0) {
                    std::cerr << "Error: Failed to forward packet" << std::endl;
                } else {
                    std::cout << "  -> Forwarded " << tx_result << " bytes" << std::endl;
                }
            }
        }
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

// Callback function for forwarding mode (forwards all packets by default)
void on_forward_frame(const uint8_t* frame, uint32_t len) {
    // Parse packet
    Parsed parsed;
    int parse_result = parse_frame(frame, len, &parsed);
    
    if (parse_result == 0) {
        // Successfully parsed - decide action based on rule
        ActionType action = decide(&g_rule, &parsed);
        
        if (action == ACTION_DROP) {
            // Print decision line and drop packet
            std::cout << "DECISION: DROP - ";
            parsed_print(&parsed);
            return;  // Drop packet (do nothing else)
        } else {
            // Forward packet (either ACTION_FORWARD or ACTION_PRINT in forward mode)
            std::cout << "FORWARD: ";
            parsed_print(&parsed);
            
            int tx_result = tx_send(frame, len);
            if (tx_result < 0) {
                std::cerr << "Error: Failed to forward packet" << std::endl;
            } else {
                std::cout << "  -> Forwarded " << tx_result << " bytes" << std::endl;
            }
        }
    } else {
        // Parse failed - still try to forward raw frame
        std::cout << "FORWARD RAW: Length=" << len << " (parse error: " << parse_result << ")" << std::endl;
        
        int tx_result = tx_send(frame, len);
        if (tx_result < 0) {
            std::cerr << "Error: Failed to forward raw packet" << std::endl;
        } else {
            std::cout << "  -> Forwarded " << tx_result << " bytes" << std::endl;
        }
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
        
        // Parse optional --rule argument
        for (int i = 4; i < argc; i += 2) {
            if (i + 1 >= argc) {
                std::cerr << "Error: --rule requires a value." << std::endl;
                print_usage(argv[0]);
                return 1;
            }
            
            if (std::string(argv[i]) == "--rule") {
                int rule_result = rule_parse(argv[i + 1], &g_rule);
                if (rule_result < 0) {
                    std::cerr << "Error: Failed to parse rule '" << argv[i + 1] 
                              << "' (error code: " << rule_result << ")" << std::endl;
                    return 1;
                }
                std::cout << "Using rule: ";
                rule_print(&g_rule);
            } else {
                std::cerr << "Error: Unknown argument '" << argv[i] << "'" << std::endl;
                print_usage(argv[0]);
                return 1;
            }
        }
        
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
    } else if (command == "forward") {
        if (argc < 6) {
            std::cerr << "Error: forward command requires --in <iface_in> --out <iface_out> arguments." << std::endl;
            print_usage(argv[0]);
            return 1;
        }

        std::string iface_in, iface_out;
        bool found_in = false, found_out = false;

        // Parse --in and --out arguments
        for (int i = 2; i < argc - 1; i += 2) {
            if (std::string(argv[i]) == "--in") {
                iface_in = argv[i + 1];
                found_in = true;
            } else if (std::string(argv[i]) == "--out") {
                iface_out = argv[i + 1];
                found_out = true;
            } else if (std::string(argv[i]) == "--rule") {
                int rule_result = rule_parse(argv[i + 1], &g_rule);
                if (rule_result < 0) {
                    std::cerr << "Error: Failed to parse rule '" << argv[i + 1] 
                              << "' (error code: " << rule_result << ")" << std::endl;
                    return 1;
                }
                std::cout << "Using rule: ";
                rule_print(&g_rule);
            } else {
                std::cerr << "Error: Unknown argument '" << argv[i] << "'" << std::endl;
                print_usage(argv[0]);
                return 1;
            }
        }

        if (!found_in || !found_out) {
            std::cerr << "Error: forward command requires both --in and --out arguments." << std::endl;
            print_usage(argv[0]);
            return 1;
        }

        // Set forward mode
        g_forward_mode = true;

        // Open transmitter
        if (tx_open(iface_out.c_str()) < 0) {
            return 1;
        }

        // Open TPACKET_V3 capture on input interface
        if (tpv3_open(iface_in.c_str()) < 0) {
            tx_close();
            return 1;
        }

        std::cout << "Forwarding packets from " << iface_in << " to " << iface_out << std::endl;
        std::cout << "Press Ctrl+C to stop..." << std::endl;

        // Main forwarding loop
        while (true) {
            // Poll for packets (1 second timeout)
            int ret = tpv3_poll(1000);
            if (ret < 0) {
                std::cerr << "Error: poll() failed" << std::endl;
                break;
            } else if (ret > 0) {
                // Process available packets
                int packets = tpv3_next(on_forward_frame);
                if (packets < 0) {
                    std::cerr << "Error: failed to process packets" << std::endl;
                    break;
                }
            }
            // If ret == 0, timeout occurred, continue polling
        }

        tpv3_close();
        tx_close();
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
