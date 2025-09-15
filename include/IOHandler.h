#pragma once

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <thread>
#include <atomic>
#include <cstdint>
#include <condition_variable>

#define IOHANDLER_DEFAULT_BUFFER_SIZE 1000

/**
 * IOHandler - Singleton class for raw packet capture.
 *
 * Reads raw bytes from socket, and stores in a shared buffer.
 */


class IOHandler {
public:
    // Singleton access
    static IOHandler& getInstance();
    
    // Delete copy constructor and assignment operator
    IOHandler(const IOHandler&) = delete;
    IOHandler& operator=(const IOHandler&) = delete;
    
    // Core functionality
    bool startCapture(const std::string& interface_name);
    void stopCapture();
    bool isCapturing() const;
    // Read and remove packet from the buffer.
    bool readPacket(std::vector<uint8_t>& packet_out);
    // Wait for a new packet to be available.
    void waitForData();

    // Set the size of the buffer. Returns true if successful.
    bool setBufferSize(size_t buffer_size);
    
private:
    // Private constructor for singleton
    IOHandler();
    ~IOHandler();
    
    void packetCaptureLoop();
    // Write packet data to buffer.
    void writePacket(const std::vector<uint8_t>& packet);
    
    // Member variables
    static std::unique_ptr<IOHandler> instance_;
    static std::mutex instance_mutex_;
    
    mutable std::mutex buffer_mutex_;
    std::condition_variable buffer_not_empty_;
    std::condition_variable buffer_not_full_;
    // Circular buffer of packets.
    std::vector<std::vector<uint8_t>> packet_buffer_;
    size_t buffer_head_;
    size_t buffer_tail_;
    size_t buffer_count_;
    size_t buffer_size_;
    
    std::string interface_name_;
    bool capturing_;
    
    // Capture thread management
    std::thread capture_thread_;
    std::atomic<bool> should_stop_capture_;
    
    // Friend class for unique_ptr access to destructor
    friend class std::default_delete<IOHandler>;
};