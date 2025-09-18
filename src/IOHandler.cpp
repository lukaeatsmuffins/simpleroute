#include "IOHandler.h"
#include <chrono>
#include <cstring>
#include <iostream>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>

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
    , tpv3_socket_(-1)
    , tpv3_ring_buffer_(nullptr)
    , tpv3_req_(new struct tpacket_req3())
    , tpv3_open_(false)
    , should_stop_capture_(false) {
    packet_buffer_.resize(buffer_size_);
}

IOHandler::~IOHandler() {
    stopCapture();
    closeTPV3();
    delete static_cast<struct tpacket_req3*>(tpv3_req_);
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


size_t IOHandler::getBufferSize() const {
    std::lock_guard<std::mutex> lock(buffer_mutex_);
    return buffer_size_;
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
    // Open TPACKET_V3 for this interface
    if (!openTPV3(interface_name_)) {
        std::cerr << "Failed to open TPACKET_V3 on interface: " << interface_name_ << std::endl;
        return;
    }
    
    while (!should_stop_capture_) {
        // Poll for packets.
        int poll_result = pollTPV3(IOHANDLER_POLL_TIMEOUT_MS);
        if (poll_result < 0) {
            std::cerr << "TPACKET_V3 poll failed" << std::endl;
            break;
        } else if (poll_result > 0) {
            // Process available packets.
            processTPV3Packets();
        }
        // If poll_result == 0, timeout occurred, continue
    }
    
    closeTPV3();
}

bool IOHandler::openTPV3(const std::string& interface_name) {
    // TPACKET_V3 configuration constants.
    static const int TPACKET_V3_BLOCK_SIZE = 1024 * 1024;
    static const int TPACKET_V3_BLOCK_NR = 64;
    static const int TPACKET_V3_FRAME_SIZE = 2048;
    static const int TPACKET_V3_TIMEOUT_MS = IOHANDLER_POLL_TIMEOUT_MS;
    
    // Create raw socket.
    tpv3_socket_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (tpv3_socket_ < 0) {
        std::cerr << "Error: Failed to create raw socket for TPACKET_V3" << std::endl;
        return false;
    }

    // Get interface index.
    int ifindex = if_nametoindex(interface_name.c_str());
    if (ifindex == 0) {
        std::cerr << "Error: Interface '" << interface_name << "' not found" << std::endl;
        close(tpv3_socket_);
        tpv3_socket_ = -1;
        return false;
    }

    // Set TPACKET_V3 version.
    int version = TPACKET_V3;
    if (setsockopt(tpv3_socket_, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) < 0) {
        std::cerr << "Error: Failed to set PACKET_VERSION: " << strerror(errno) << std::endl;
        close(tpv3_socket_);
        tpv3_socket_ = -1;
        return false;
    }

    // Configure TPACKET_V3.
    struct tpacket_req3* req = static_cast<struct tpacket_req3*>(tpv3_req_);
    memset(req, 0, sizeof(*req));
    req->tp_block_size = TPACKET_V3_BLOCK_SIZE;
    req->tp_block_nr = TPACKET_V3_BLOCK_NR;
    req->tp_frame_size = TPACKET_V3_FRAME_SIZE;
    req->tp_frame_nr = (TPACKET_V3_BLOCK_SIZE * TPACKET_V3_BLOCK_NR) / TPACKET_V3_FRAME_SIZE;
    req->tp_retire_blk_tov = TPACKET_V3_TIMEOUT_MS;
    req->tp_sizeof_priv = 0;
    req->tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

    if (setsockopt(tpv3_socket_, SOL_PACKET, PACKET_RX_RING, req, sizeof(*req)) < 0) {
        std::cerr << "Error: Failed to set PACKET_RX_RING: " << strerror(errno) << std::endl;
        close(tpv3_socket_);
        tpv3_socket_ = -1;
        return false;
    }

    // Memory map the ring buffer.
    tpv3_ring_buffer_ = mmap(nullptr, req->tp_block_size * req->tp_block_nr,
                            PROT_READ | PROT_WRITE, MAP_SHARED, tpv3_socket_, 0);
    if (tpv3_ring_buffer_ == MAP_FAILED) {
        std::cerr << "Error: Failed to mmap ring buffer: " << strerror(errno) << std::endl;
        close(tpv3_socket_);
        tpv3_socket_ = -1;
        return false;
    }

    // Bind socket to interface.
    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = ifindex;

    if (bind(tpv3_socket_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "Error: Failed to bind to interface '" << interface_name << "': " << strerror(errno) << std::endl;
        munmap(tpv3_ring_buffer_, req->tp_block_size * req->tp_block_nr);
        close(tpv3_socket_);
        tpv3_socket_ = -1;
        tpv3_ring_buffer_ = nullptr;
        return false;
    }

    tpv3_open_ = true;
    return true;
}

void IOHandler::closeTPV3() {
    if (tpv3_ring_buffer_ && tpv3_ring_buffer_ != MAP_FAILED) {
        struct tpacket_req3* req = static_cast<struct tpacket_req3*>(tpv3_req_);
        munmap(tpv3_ring_buffer_, req->tp_block_size * req->tp_block_nr);
        tpv3_ring_buffer_ = nullptr;
    }

    if (tpv3_socket_ >= 0) {
        close(tpv3_socket_);
        tpv3_socket_ = -1;
    }
    
    tpv3_open_ = false;
}

int IOHandler::pollTPV3(int timeout_ms) {
    if (tpv3_socket_ < 0) {
        return -1;
    }

    struct pollfd pfd;
    pfd.fd = tpv3_socket_;
    pfd.events = POLLIN;
    pfd.revents = 0;

    int ret = poll(&pfd, 1, timeout_ms);
    if (ret < 0) {
        std::cerr << "Error: TPACKET_V3 poll() failed: " << strerror(errno) << std::endl;
        return -1;
    }

    return ret;
}

int IOHandler::processTPV3Packets() {
    if (tpv3_socket_ < 0 || !tpv3_ring_buffer_) {
        return -1;
    }

    int packets_processed = 0;
    static unsigned int current_block = 0;

    // Process available blocks.
    struct tpacket_req3* req = static_cast<struct tpacket_req3*>(tpv3_req_);
    for (unsigned int i = 0; i < req->tp_block_nr; ++i) {
        unsigned int block_idx = (current_block + i) % req->tp_block_nr;
        struct tpacket_block_desc* block_desc = 
            (struct tpacket_block_desc*)((char*)tpv3_ring_buffer_ + block_idx * req->tp_block_size);

        // Check if block has packets ready for user space.
        if (!(block_desc->hdr.bh1.block_status & TP_STATUS_USER)) {
            continue;
        }

        // Process all packets in this block.
        uint8_t* block_start = (uint8_t*)block_desc;
        uint32_t offset = block_desc->hdr.bh1.offset_to_first_pkt;
        uint32_t num_packets = block_desc->hdr.bh1.num_pkts;

        for (uint32_t pkt = 0; pkt < num_packets; ++pkt) {
            struct tpacket3_hdr* frame_hdr = (struct tpacket3_hdr*)(block_start + offset);
            
            // Validate frame header.
            if (offset >= req->tp_block_size || 
                frame_hdr->tp_next_offset == 0 ||
                frame_hdr->tp_len == 0 || frame_hdr->tp_len > 65536) {
                break;
            }

            // Extract frame data
            uint8_t* frame_data = (uint8_t*)frame_hdr + frame_hdr->tp_mac;
            uint32_t frame_len = frame_hdr->tp_len;

            // Convert to vector and write to shared buffer
            std::vector<uint8_t> packet(frame_data, frame_data + frame_len);
            writePacket(packet);
            packets_processed++;

            // Move to next frame
            offset += frame_hdr->tp_next_offset;
            
            if (pkt == num_packets - 1) {
                break;
            }
        }

        // Mark block as processed.
        block_desc->hdr.bh1.block_status = TP_STATUS_KERNEL;
        current_block = (block_idx + 1) % req->tp_block_nr;
    }

    return packets_processed;
}
