#include "IOHandler.h"
#include "l2_parser.h"
#include "l3_parser.h"
#include "l4_parser.h"
#include "parser.h"
#include "stats.h"
#include "tcp_flow_analyzer.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <cstdio>
#include <vector>
#include <fstream>
#include <string>
#include <algorithm>

#define MAX_BUFFER_SIZE 10000
#define MAX_CAPTURE_TIME 120

enum InputOption {
    CAPTURE_PACKETS = 1,
    SET_CAPTURE_OPTIONS = 2,
    SET_FILTER = 3,
    GET_STATS = 4,
    ANALYZE_FLOWS = 5,
    CONSOLE_EXIT = 6,
};

enum CaptureOption {
    SET_CAPTURE_INTERFACE = 1,
    SET_CAPTURE_BUFFER_SIZE = 2,
    SET_CAPTURE_TIME = 3,
    SET_CAPTURE_FILE_NAME = 4,
    CAPTURE_OPTION_EXIT = 5,
};

struct Globals {
    int capture_time = -1;
    int buffer_size = -1;
    std::string capture_interface = "";
    std::string capture_file_name = "";
    Stats stats_;
} globals_;


void handleConsole();

void handlePacketCapture();
int checkGlobals();

void handleSetCaptureOptions();
void handleSetBufferSize();
void handleSetCaptureInterface();
void handleSetCaptureTime();
void handleSetCaptureFileName();

void handleSetFilter();

void handleGetStats();
void handleAnalyzeFlows();
void browseFlowsInteractive(const TCPFlowAnalysis& analysis);
int handleFlowNavigation(const TCPFlowAnalysis& analysis, size_t& current_flow);
void printFlowData(const TCPFlowAnalysis& analysis, size_t current_flow, size_t total_flows);

void clearScreen() { std::cout << "\033[2J\033[1;1H"; }
void pressEnterToContinue();

void printUsage(const char* program_name);
bool parseCommandLineArgs(int argc, char* argv[]);
void runNonInteractiveMode();

int main(int argc, char* argv[]) {
    if (argc > 1) {
        if (parseCommandLineArgs(argc, argv)) {
            runNonInteractiveMode();
            return 0;
        } else {
            return 1;
        }
    }
    
    // Run interactive mode if no arguments provided.
    handleConsole();
    return 0;
}


void handleConsole() {
    std::cout << "Packet Sniffer - Interactive Mode\n";
    std::cout << "=====================================\n\n";

    while(true) {
        clearScreen();
        std::cout << "Select an option:" << std::endl
                  << "1. Capture packets" << std::endl
                  << "2. Set capture options" << std::endl
                  << "3. Set a filter" << std::endl
                  << "4. Get stats" << std::endl
                  << "5. Analyze flows" << std::endl
                  << "6. Exit" << std::endl;

        int choice;
        std::cin >> choice;

        switch (static_cast<InputOption>(choice)) {
            case InputOption::CAPTURE_PACKETS:
                handlePacketCapture();
                break;
            case InputOption::SET_CAPTURE_OPTIONS:
                handleSetCaptureOptions();
                continue;
            case InputOption::SET_FILTER:
                handleSetFilter();
                continue;
            case InputOption::GET_STATS:
                handleGetStats();
                break;
            case InputOption::ANALYZE_FLOWS:
                handleAnalyzeFlows();
                break;
            case InputOption::CONSOLE_EXIT:
                return;
            default:
                std::cout << "Invalid choice" << std::endl;
                pressEnterToContinue();
        }
    }
}

int checkGlobals() {
    if (globals_.capture_interface.empty()) {
        std::cerr << "ERROR: Capture interface is not set" << std::endl;
        return -1;
    }
    if (globals_.capture_time <= 0) {
        std::cerr << "ERROR: Capture time is not set" << std::endl;
        return -1;
    }
    if (globals_.buffer_size <= 0) {
        std::cerr << "ERROR: Buffer size is not set" << std::endl;
        return -1;
    }
    if (globals_.capture_file_name.empty()) {
        std::cerr << "ERROR: Capture file name is not set" << std::endl;
        return -1;
    }
    return 0;
}

void handlePacketCapture() {
    // Ensure capture options are set.
    if (checkGlobals()) {
        return;
    }

    IOHandler& handler = IOHandler::getInstance();
    bool capture_started = handler.startCapture(globals_.capture_interface);

    // Start packet capture.
    std::cout << "Starting packet capture on " 
              << globals_.capture_interface 
              << "..." 
              << std::endl;
              
    if (!capture_started) {
        std::cerr << "ERROR: Failed to start packet capture" << std::endl;
        return;
    }
    std::cout << "Packet capture started successfully" << std::endl;
    
    // Open capture file for writing.
    std::ofstream capture_file(globals_.capture_file_name);
    if (!capture_file.is_open()) {
        std::cerr << "ERROR: Failed to open capture file" << std::endl;
        handler.stopCapture();
        return;
    }
    
    std::cout << "Capturing packets for " 
              << globals_.capture_time 
              << " seconds..." 
              << std::endl;
    
    int packet_count = 0;
    auto start_time = std::chrono::steady_clock::now();
    auto end_time = start_time + std::chrono::seconds(globals_.capture_time);
    
    while (std::chrono::steady_clock::now() < end_time) {
        std::vector<uint8_t> packet;
        
        handler.waitForData();
        
        if (handler.readPacket(packet)) {
            packet_count++;
            
            ParsedPacket parsed = Parser::parse_packet(packet, 0);
            
            std::string serialized = Parser::serialize_packet(parsed);
            capture_file << serialized << std::endl;
        }
    }
    
    // Stop capture and cleanup.
    std::cout << "Stopping Packet Capture" << std::endl;
    std::cout << "Captured " 
              << packet_count 
              << " packets in " 
              << globals_.capture_time 
              << " seconds" 
              << std::endl;
    std::cout << "Packets saved to " 
              << globals_.capture_file_name 
              << std::endl;
    
    handler.stopCapture();
    capture_file.close();
}

void handleSetCaptureOptions() {
    while(true) {
        clearScreen();
        std::cout << "Set capture options:" << std::endl
                  << "1. Set capture interface" << std::endl
                  << "2. Set capture buffer size" << std::endl
                  << "3. Set capture time" << std::endl
                  << "4. Set capture file name" << std::endl
                  << "5. Exit" << std::endl;

        int choice;
        std::cin >> choice;

        switch (static_cast<CaptureOption>(choice)) {
            case CaptureOption::SET_CAPTURE_INTERFACE:
                handleSetCaptureInterface();
                break;
            case CaptureOption::SET_CAPTURE_BUFFER_SIZE:
                handleSetBufferSize();
                break;
            case CaptureOption::SET_CAPTURE_TIME:
                handleSetCaptureTime();
                break;
            case CaptureOption::SET_CAPTURE_FILE_NAME:
                handleSetCaptureFileName();
                break;
            case CaptureOption::CAPTURE_OPTION_EXIT:
                return;
            default:
                std::cout << "Invalid choice" << std::endl;
                break;
        }
        pressEnterToContinue();
    }
}

void handleSetBufferSize() {
    std::cout << "Set buffer size:" << std::endl
              << "Enter buffer size: ";
    int buffer_size;
    std::cin >> buffer_size;

    if (buffer_size <= 0) {
        std::cerr << "ERROR: Buffer size must be greater than 0" << std::endl;
        return;
    }

    if (buffer_size > MAX_BUFFER_SIZE) {
        std::cerr << "ERROR: Buffer size must be less than " << MAX_BUFFER_SIZE << std::endl;
        return;
    }

    IOHandler& handler = IOHandler::getInstance();
    bool buffer_set = handler.setBufferSize(buffer_size);

    if (!buffer_set) {
        std::cerr << "ERROR: Failed to set buffer size" << std::endl;
        return;
    }

    globals_.buffer_size = buffer_size;
}

void handleSetCaptureInterface() {
    std::cout << "Enter capture interface: ";
    std::string capture_interface;
    std::cin >> capture_interface;
    globals_.capture_interface = capture_interface;
}

void handleSetCaptureTime() {
    std::cout << "Enter capture time: ";
    int capture_time;
    std::cin >> capture_time;

    if (capture_time <= 0) {
        std::cerr << "ERROR: Capture time must be greater than 0" << std::endl;
        return;
    }

    if (capture_time > MAX_CAPTURE_TIME) {
        std::cerr << "ERROR: Capture time must be less than " << MAX_CAPTURE_TIME << std::endl;
        return;
    }

    globals_.capture_time = capture_time;
}

void handleSetCaptureFileName() {
    std::cout << "Enter capture file name: ";
    std::string capture_file_name;
    std::cin >> capture_file_name;
    globals_.capture_file_name = capture_file_name;
}

void handleSetFilter() {
    std::cout << "Enter filter: ";
    std::string filter;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::getline(std::cin, filter);
    if (!globals_.stats_.setFilter(filter)) {
        std::cerr << "ERROR: Failed to set filter" << std::endl;
        return;
    }
    std::cout << "Filter set successfully" << std::endl;
}

void handleGetStats() {
    clearScreen();
    if (globals_.capture_file_name.empty()) {
        std::cerr << "ERROR: Capture file name is not set" << std::endl;
        pressEnterToContinue();
        return;
    }
    std::cout << "================" << std::endl;
    std::cout << "Stats" << std::endl;
    std::cout << "================" << std::endl;
    FilterStats stats = globals_.stats_.applyFilter(globals_.capture_file_name);
    std::cout << "Stats: " 
              << stats.packet_count 
              << " packets, " 
              << stats.total_bytes 
              << " bytes" 
              << std::endl;

    std::cout << globals_.stats_.getGroupingReport(globals_.capture_file_name, GroupBy::SRC_IP)
              << globals_.stats_.getGroupingReport(globals_.capture_file_name, GroupBy::DST_IP)
              << globals_.stats_.getGroupingReport(globals_.capture_file_name, GroupBy::SRC_PORT)
              << globals_.stats_.getGroupingReport(globals_.capture_file_name, GroupBy::DST_PORT)
              << globals_.stats_.getGroupingReport(globals_.capture_file_name, GroupBy::PACKET_SIZE)
              << globals_.stats_.getGroupingReport(globals_.capture_file_name, GroupBy::SRC_MAC)
              << globals_.stats_.getGroupingReport(globals_.capture_file_name, GroupBy::DST_MAC)
              << globals_.stats_.getGroupingReport(globals_.capture_file_name, GroupBy::VLAN_ID)
              << globals_.stats_.getGroupingReport(globals_.capture_file_name, GroupBy::PROTOCOL)
              << std::endl;
    pressEnterToContinue();
}

void pressEnterToContinue() {
    std::cout << "Press Enter to continue..." << std::endl;
    std::string input;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::getline(std::cin, input);
}

void handleAnalyzeFlows() {
    clearScreen();
    if (globals_.capture_file_name.empty()) {
        std::cerr << "ERROR: Capture file name is not set" << std::endl;
        return;
    }
    
    std::cout << "================" << std::endl;
    std::cout << "TCP Flow Analysis" << std::endl;
    std::cout << "================" << std::endl;
    
    TCPFlowAnalysis analysis = TCPFlowAnalyzer::analyzeFlows(globals_.capture_file_name);
    
    std::cout << TCPFlowAnalyzer::generateFlowReport(analysis) << std::endl;
    
    std::cout << "\nPress Enter to start interactive flow browsing...";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cin.get();
    
    browseFlowsInteractive(analysis);
}

void printUsage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]\n\n";
    std::cout << "Packet Sniffer - Capture and analyze network packets\n\n";
    std::cout << "OPTIONS:\n";
    std::cout << "  --help                    Show this help message\n";
    std::cout << "  --interface <name>         Network interface to capture from (required)\n";
    std::cout << "  --capture-time <seconds>   Duration to capture packets (default: 30)\n";
    std::cout << "  --buffer-size <size>       Capture buffer size (default: 1000)\n";
    std::cout << "  --output <filename>        Output file for captured packets (required)\n";
    std::cout << "  --filter <filter_string>   Filter packets (e.g., 'protocol=tcp port=80')\n";
    std::cout << "  --stats-only              Only show statistics from existing capture file\n";
    std::cout << "  --analyze-flows           Analyze TCP flows from capture file\n\n";
    std::cout << "EXAMPLES:\n";
    std::cout << "  " << program_name << " --interface eth0 --capture-time 60 --output capture.txt\n";
    std::cout << "  " << program_name << " --interface wlan0 --filter 'protocol=tcp' --output tcp_capture.txt\n";
    std::cout << "  " << program_name << " --stats-only --output capture.txt\n";
    std::cout << "  " << program_name << " --interface eth0 --filter 'dst_port=25565' --capture-time 120 --output minecraft.txt\n";
    std::cout << "  " << program_name << " --analyze-flows --output tcp_flows.txt\n\n";
    std::cout << "FILTER SYNTAX:\n";
    std::cout << "  protocol=<name>           Filter by protocol (tcp, udp, icmp, etc.)\n";
    std::cout << "  src_ip=<address>          Filter by source IP address\n";
    std::cout << "  dst_ip=<address>          Filter by destination IP address\n";
    std::cout << "  src_port=<port>           Filter by source port\n";
    std::cout << "  dst_port=<port>           Filter by destination port\n";
    std::cout << "  src_mac=<address>         Filter by source MAC address\n";
    std::cout << "  dst_mac=<address>         Filter by destination MAC address\n";
    std::cout << "  vlan_id=<id>              Filter by VLAN ID\n";
    std::cout << "  min_size=<bytes>          Filter by minimum packet size\n";
    std::cout << "  max_size=<bytes>          Filter by maximum packet size\n\n";
}

enum class AnalysisMode {
    CAPTURE_AND_STATS,
    STATS_ONLY,
    ANALYZE_FLOWS
} analysis_mode = AnalysisMode::CAPTURE_AND_STATS;

bool parseCommandLineArgs(int argc, char* argv[]) {
    bool interface_set = false;
    bool output_set = false;
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "--help" || arg == "-h") {
            printUsage(argv[0]);
            return false;
        }
        else if (arg == "--stats-only") {
            analysis_mode = AnalysisMode::STATS_ONLY;
        }
        else if (arg == "--analyze-flows") {
            analysis_mode = AnalysisMode::ANALYZE_FLOWS;
        }
        else if (arg == "--interface" && i + 1 < argc) {
            globals_.capture_interface = argv[++i];
            interface_set = true;
        }
        else if (arg == "--capture-time" && i + 1 < argc) {
            int time = std::stoi(argv[++i]);
            if (time <= 0 || time > MAX_CAPTURE_TIME) {
                std::cerr << "ERROR: Capture time must be between 1 and " << MAX_CAPTURE_TIME << " seconds\n";
                return false;
            }
            globals_.capture_time = time;
        }
        else if (arg == "--buffer-size" && i + 1 < argc) {
            int buffer_size = std::stoi(argv[++i]);
            if (buffer_size <= 0 || buffer_size > MAX_BUFFER_SIZE) {
                std::cerr << "ERROR: Buffer size must be between 1 and " << MAX_BUFFER_SIZE << "\n";
                return false;
            }
            IOHandler& handler = IOHandler::getInstance();
            bool buffer_set = handler.setBufferSize(buffer_size);
        
            if (!buffer_set) {
                std::cerr << "ERROR: Failed to set buffer size" << std::endl;
                return false;
            }
            globals_.buffer_size = buffer_size;
        }
        else if (arg == "--output" && i + 1 < argc) {
            globals_.capture_file_name = argv[++i];
            output_set = true;
        }
        else if (arg == "--filter" && i + 1 < argc) {
            std::string filter = argv[++i];
            if (!globals_.stats_.setFilter(filter)) {
                std::cerr << "ERROR: Invalid filter syntax: " << filter << "\n";
                return false;
            }
        }
        else {
            std::cerr << "ERROR: Unknown argument: " << arg << "\n";
            std::cerr << "Use --help for usage information\n";
            return false;
        }
    }
    
    // Set defaults if not specified.
    if (globals_.capture_time == -1) {
        globals_.capture_time = IOHANDLER_DEFAULT_CAPTURE_TIME;
    }
    if (globals_.buffer_size == -1) {
        globals_.buffer_size = IOHANDLER_DEFAULT_BUFFER_SIZE;
    }
    
    // Validate required arguments.
    if (analysis_mode == AnalysisMode::STATS_ONLY || analysis_mode == AnalysisMode::ANALYZE_FLOWS) {
        if (!output_set) {
            std::cerr << "ERROR: --output is required for --stats-only and --analyze-flows modes\n";
            return false;
        }
    } else {
        if (!interface_set) {
            std::cerr << "ERROR: --interface is required for packet capture\n";
            return false;
        }
        if (!output_set) {
            std::cerr << "ERROR: --output is required for packet capture\n";
            return false;
        }
    }
    
    return true;
}

void runNonInteractiveMode() {
    std::cout << "Packet Sniffer - Non-Interactive Mode\n";
    std::cout << "=====================================\n\n";
    
    switch (analysis_mode) {
        case AnalysisMode::STATS_ONLY:
            std::cout << "Showing statistics from: " << globals_.capture_file_name << "\n\n";
            handleGetStats();
            break;
            
        case AnalysisMode::ANALYZE_FLOWS:
            std::cout << "Analyzing TCP flows from: " << globals_.capture_file_name << "\n\n";
            handleAnalyzeFlows();
            break;
            
        case AnalysisMode::CAPTURE_AND_STATS:
        default:
            std::cout << "Configuration:\n";
            std::cout << "  Interface: " << globals_.capture_interface << "\n";
            std::cout << "  Capture Time: " << globals_.capture_time << " seconds\n";
            std::cout << "  Buffer Size: " << globals_.buffer_size << "\n";
            std::cout << "  Output File: " << globals_.capture_file_name << "\n";
            if (globals_.stats_.hasActiveFilter()) {
                std::cout << "  Filter: Active\n";
            } else {
                std::cout << "  Filter: None (capture all packets)\n";
            }
            
            handlePacketCapture();
            
            std::cout << "\nCapture completed. Showing statistics...\n\n";
            handleGetStats();
            break;
    }
}

void browseFlowsInteractive(const TCPFlowAnalysis& analysis) {
    if (analysis.flows.empty()) {
        std::cout << "No TCP flows found in the capture file." << std::endl;
        return;
    }
    
    size_t current_flow = 0;
    size_t total_flows = TCPFlowAnalyzer::getFlowCount(analysis);
    
    while (true) {
        clearScreen();
        printFlowData(analysis, current_flow, total_flows);
        if(handleFlowNavigation(analysis, current_flow) == 1) {
            break;
        }
    }
}

void printFlowData(const TCPFlowAnalysis& analysis, size_t current_flow, size_t total_flows) {
    std::cout << "================\n";
    std::cout << "TCP Flow Browser\n";
    std::cout << "================\n";
    std::cout << "Flow " << (current_flow + 1) << " of " << total_flows << "\n\n";
    
    const auto& [flow_id, flow] = TCPFlowAnalyzer::getCurrentFlow(analysis, current_flow);
    
    std::cout << "Flow ID: " << flow_id << "\n";
    std::cout << "Packets: " << (flow.packets_sent + flow.packets_received) 
                << " (" << flow.packets_sent << " sent, " << flow.packets_received << " received)\n";
    std::cout << "Bytes: " << (flow.bytes_sent + flow.bytes_received) 
                << " (" << flow.bytes_sent << " sent, " << flow.bytes_received << " received)\n";
    std::cout << "TCP Flags: SYN:" << flow.syn_packets 
                << " SYN-ACK:" << flow.syn_ack_packets 
                << " ACK:" << flow.ack_packets 
                << " FIN:" << flow.fin_packets 
                << " RST:" << flow.rst_packets << "\n";
    
    if (flow.retransmissions > 0) {
        std::cout << "Retransmissions: " << flow.retransmissions << "\n";
    }
    
    std::cout << "Status: " << (flow.connection_established ? "Established" : "Not Established");
    if (flow.connection_closed) {
        std::cout << ", Closed";
    }
    std::cout << "\n";
    
    if (flow.max_window_size > 0) {
        std::cout << "Window Size: " << flow.min_window_size << " - " << flow.max_window_size << "\n";
    }
}

int handleFlowNavigation(const TCPFlowAnalysis& analysis, size_t& current_flow) {
    std::cout << "\nControls: j=next, k=previous, q=quit\n";
    std::cout << "Choice: ";
    
    char choice;
    std::cin >> choice;
    
    switch (choice) {
        case 'j':
        case 'J': {
            auto [next_flow_id, next_flow] = TCPFlowAnalyzer::getNextFlow(analysis, current_flow);
            if (!next_flow_id.empty()) {
                current_flow++;
            }
            break;
        }
        case 'k':
        case 'K': {
            auto [prev_flow_id, prev_flow] = TCPFlowAnalyzer::getPrevFlow(analysis, current_flow);
            if (!prev_flow_id.empty()) {
                current_flow--;
            }
            break;
        }
        case 'q':
        case 'Q':
            return 1;
    }
    return 0;
}