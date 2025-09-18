#include "IOHandler.h"
#include "l2_parser.h"
#include "l3_parser.h"
#include "l4_parser.h"
#include "parser.h"
#include "stats.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <cstdio>
#include <vector>
#include <fstream>

#define MAX_BUFFER_SIZE 10000
#define MAX_CAPTURE_TIME 120

enum InputOption {
    CAPTURE_PACKETS = 1,
    SET_CAPTURE_OPTIONS = 2,
    SET_FILTER = 3,
    GET_STATS = 4,
    CONSOLE_EXIT = 5,
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

void clearScreen() { std::cout << "\033[2J\033[1;1H"; }

int main() {
    handleConsole();
}


void handleConsole() {
    // Prompt the user for whether or not they want to capture packets, set a filter, or
    // get stats.

    while(true) {
        clearScreen();
        std::cout << "Select an option:" << std::endl;
        std::cout << "1. Capture packets" << std::endl;
        std::cout << "2. Set capture options" << std::endl;
        std::cout << "3. Set a filter" << std::endl;
        std::cout << "4. Get stats" << std::endl;
        std::cout << "5. Exit" << std::endl;

        int choice;
        std::cin >> choice;

        switch (static_cast<InputOption>(choice)) {
            case CAPTURE_PACKETS:
                handlePacketCapture();
                break;
            case SET_CAPTURE_OPTIONS:
                handleSetCaptureOptions();
                break;
            case SET_FILTER:
                handleSetFilter();
                break;
            case GET_STATS:
                handleGetStats();
                break;
            case CONSOLE_EXIT:
                return;
            default:
                std::cout << "Invalid choice" << std::endl;
                break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
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
    std::cout << "Starting packet capture on " << globals_.capture_interface << "..." << std::endl;
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
    
    std::cout << "Capturing packets for " << globals_.capture_time << " seconds..." << std::endl;
    
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
    
    // Stop capture and cleanup
    std::cout << "Stopping Packet Capture" << std::endl;
    std::cout << "Captured " << packet_count << " packets in " << globals_.capture_time << " seconds" << std::endl;
    std::cout << "Packets saved to " << globals_.capture_file_name << std::endl;
    
    handler.stopCapture();
    capture_file.close();
}

void handleSetCaptureOptions() {
    while(true) {
        clearScreen();
        std::cout << "Set capture options:" << std::endl;
        std::cout << "1. Set capture interface" << std::endl;
        std::cout << "2. Set capture buffer size" << std::endl;
        std::cout << "3. Set capture time" << std::endl;
        std::cout << "4. Set capture file name" << std::endl;
        std::cout << "5. Exit" << std::endl;

        int choice;
        std::cin >> choice;

        switch (static_cast<CaptureOption>(choice)) {
            case SET_CAPTURE_INTERFACE:
                handleSetCaptureInterface();
                break;
            case SET_CAPTURE_BUFFER_SIZE:
                handleSetBufferSize();
                break;
            case SET_CAPTURE_TIME:
                handleSetCaptureTime();
                break;
            case SET_CAPTURE_FILE_NAME:
                handleSetCaptureFileName();
                break;
            case CAPTURE_OPTION_EXIT:
                return;
            default:
                std::cout << "Invalid choice" << std::endl;
                break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
}

void handleSetBufferSize() {
    std::cout << "Set buffer size:" << std::endl;
    std::cout << "Enter buffer size: ";
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
    std::cin >> filter;
    if (!globals_.stats_.setFilter(filter)) {
        std::cerr << "ERROR: Failed to set filter" << std::endl;
        return;
    }
}

void handleGetStats() {

    FilterStats stats = globals_.stats_.applyFilter(globals_.capture_file_name);
    std::cout << "Stats: " << stats.packet_count << " packets, " << stats.total_bytes << " bytes" << std::endl;
}