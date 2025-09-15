#include "IOHandler.h"
#include <chrono>

std::unique_ptr<IOHandler> IOHandler::instance_ = nullptr;
std::mutex IOHandler::instance_mutex_;

IOHandler& IOHandler::getInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex_);
    if (!instance_) {
        instance_ = std::unique_ptr<IOHandler>(new IOHandler());
    }
    return *instance_;
}

IOHandler::IOHandler() 
    : buffer_head_(0)
    , buffer_tail_(0)
    , buffer_count_(0)
    , buffer_size_(IOHANDLER_DEFAULT_BUFFER_SIZE) 
    , capturing_(false)
    , should_stop_capture_(false) {
    packet_buffer_.resize(buffer_size_);
}

IOHandler::~IOHandler() {
    stopCapture();
}

bool IOHandler::startCapture(const std::string& interface_name) {
    std::lock_guard<std::mutex> lock(buffer_mutex_);
    if (capturing_) {
        return false; 
    }
    
    interface_name_ = interface_name;
    should_stop_capture_ = false;
    
    // Reset buffer state.
    buffer_head_ = 0;
    buffer_tail_ = 0;
    buffer_count_ = 0;
    
    // TODO: Initialize AF_PACKET socket here.
    
    // Start capture thread.
    capture_thread_ = std::thread(&IOHandler::packetCaptureLoop, this);
    capturing_ = true;
    
    return true;
}

void IOHandler::stopCapture() {
    {
        std::lock_guard<std::mutex> lock(buffer_mutex_);
        if (!capturing_) {
            return;
        }
        
        should_stop_capture_ = true;
        capturing_ = false;
    }
    
    // Wake up any waiting threads.
    buffer_not_empty_.notify_all();
    buffer_not_full_.notify_all();
    
    // Wait for capture thread to finish.
    if (capture_thread_.joinable()) {
        capture_thread_.join();
    }
}

bool IOHandler::isCapturing() const {
    std::lock_guard<std::mutex> lock(buffer_mutex_);
    return capturing_;
}

bool IOHandler::readPacket(std::vector<uint8_t>& packet_out) {
    std::unique_lock<std::mutex> lock(buffer_mutex_);

    // If we have no packets, return false.
    if (buffer_count_ == 0) {
        return false;
    }
    
    // Read packet from buffer.
    packet_out = std::move(packet_buffer_[buffer_tail_]);
    buffer_tail_ = (buffer_tail_ + 1) % buffer_size_;
    buffer_count_--;
    
    // Notify producer that buffer has space.
    buffer_not_full_.notify_one();
    
    return true;
}

void IOHandler::waitForData() {
    std::unique_lock<std::mutex> lock(buffer_mutex_);
    buffer_not_empty_.wait(lock, [this] { 
        return buffer_count_ > 0 || !capturing_; 
    });
}

bool IOHandler::setBufferSize(size_t buffer_size) {
    std::lock_guard<std::mutex> lock(buffer_mutex_);
    if (capturing_) {
        return false;
    }

    buffer_size_ = buffer_size;
    packet_buffer_.resize(buffer_size_);
    buffer_head_ = 0;
    buffer_tail_ = 0;
    buffer_count_ = 0;

    return true;
}

void IOHandler::writePacket(const std::vector<uint8_t>& packet) {
    std::unique_lock<std::mutex> lock(buffer_mutex_);
    
    // Wait for buffer space if full.
    buffer_not_full_.wait(lock, [this] { 
        return (buffer_count_ < buffer_size_) || should_stop_capture_; 
    });
    
    // Abort if we stopped capturing.
    if (should_stop_capture_) {
        return;
    }
    
    // Write packet to buffer.
    packet_buffer_[buffer_head_] = packet;
    buffer_head_ = (buffer_head_ + 1) % buffer_size_;
    buffer_count_++;
    
    // Notify consumer that data is available.
    buffer_not_empty_.notify_one();
}

void IOHandler::packetCaptureLoop() {
    // TODO: Implement raw packet capture loop
    // This should:
    // 1. Create AF_PACKET socket
    // 2. Bind to interface
    // 3. Loop: read raw bytes from socket
    // 4. Call writePacket() to store in shared buffer
    // 5. Check should_stop_capture_ periodically
    
    while (!should_stop_capture_) {
        // TODO: Actual packet capture implementation
        // For now, just sleep to simulate work
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        // Example of how to use writePacket:
        // std::vector<uint8_t> captured_packet = read_from_socket();
        // writePacket(captured_packet);
    }
}
