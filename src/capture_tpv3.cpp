#include "capture_tpv3.h"
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

// TPACKET_V3 configuration constants
static const int TPACKET_V3_BLOCK_SIZE = 1024 * 1024;  // 1 MiB blocks
static const int TPACKET_V3_BLOCK_NR = 64;             // 64 blocks
static const int TPACKET_V3_FRAME_SIZE = 2048;         // 2048-byte frames
static const int TPACKET_V3_TIMEOUT_MS = 1000;         // 1 second timeout

// Global state for TPACKET_V3
static int tpv3_socket = -1;
static void* tpv3_ring_buffer = nullptr;
static struct tpacket_req3 tpv3_req;

int tpv3_open(const char* ifname) {
    // Create raw socket
    tpv3_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (tpv3_socket < 0) {
        std::cerr << "Error: Failed to create raw socket. "
                  << "Make sure you have CAP_NET_RAW capability or run with sudo." << std::endl;
        return -1;
    }

    // Get interface index
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        std::cerr << "Error: Interface '" << ifname << "' not found." << std::endl;
        close(tpv3_socket);
        tpv3_socket = -1;
        return -1;
    }

    // Set TPACKET_V3 version first
    int version = TPACKET_V3;
    if (setsockopt(tpv3_socket, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) < 0) {
        std::cerr << "Error: Failed to set PACKET_VERSION: " << strerror(errno) << std::endl;
        close(tpv3_socket);
        tpv3_socket = -1;
        return -1;
    }

    // Configure TPACKET_V3
    memset(&tpv3_req, 0, sizeof(tpv3_req));
    tpv3_req.tp_block_size = TPACKET_V3_BLOCK_SIZE;
    tpv3_req.tp_block_nr = TPACKET_V3_BLOCK_NR;
    tpv3_req.tp_frame_size = TPACKET_V3_FRAME_SIZE;
    tpv3_req.tp_frame_nr = (TPACKET_V3_BLOCK_SIZE * TPACKET_V3_BLOCK_NR) / TPACKET_V3_FRAME_SIZE;
    tpv3_req.tp_retire_blk_tov = TPACKET_V3_TIMEOUT_MS;
    tpv3_req.tp_sizeof_priv = 0;
    tpv3_req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

    if (setsockopt(tpv3_socket, SOL_PACKET, PACKET_RX_RING, &tpv3_req, sizeof(tpv3_req)) < 0) {
        std::cerr << "Error: Failed to set PACKET_RX_RING: " << strerror(errno) << std::endl;
        close(tpv3_socket);
        tpv3_socket = -1;
        return -1;
    }

    // Memory map the ring buffer
    tpv3_ring_buffer = mmap(nullptr, tpv3_req.tp_block_size * tpv3_req.tp_block_nr,
                           PROT_READ | PROT_WRITE, MAP_SHARED, tpv3_socket, 0);
    if (tpv3_ring_buffer == MAP_FAILED) {
        std::cerr << "Error: Failed to mmap ring buffer: " << strerror(errno) << std::endl;
        close(tpv3_socket);
        tpv3_socket = -1;
        return -1;
    }

    // Bind socket to interface
    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = ifindex;

    if (bind(tpv3_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "Error: Failed to bind to interface '" << ifname << "': " << strerror(errno) << std::endl;
        munmap(tpv3_ring_buffer, tpv3_req.tp_block_size * tpv3_req.tp_block_nr);
        close(tpv3_socket);
        tpv3_socket = -1;
        tpv3_ring_buffer = nullptr;
        return -1;
    }

    std::cout << "TPACKET_V3 capture opened on interface: " << ifname << std::endl;
    std::cout << "Ring buffer: " << tpv3_req.tp_block_nr << " blocks of " 
              << tpv3_req.tp_block_size << " bytes each" << std::endl;
    std::cout << "Frame size: " << tpv3_req.tp_frame_size << " bytes" << std::endl;

    return 0;
}

int tpv3_poll(int timeout_ms) {
    if (tpv3_socket < 0) {
        return -1;
    }

    struct pollfd pfd;
    pfd.fd = tpv3_socket;
    pfd.events = POLLIN;
    pfd.revents = 0;

    int ret = poll(&pfd, 1, timeout_ms);
    if (ret < 0) {
        std::cerr << "Error: poll() failed: " << strerror(errno) << std::endl;
        return -1;
    }

    return ret;
}

int tpv3_next(void (*on_frame)(const uint8_t* frame, uint32_t len)) {
    if (tpv3_socket < 0 || !tpv3_ring_buffer) {
        return -1;
    }

    int packets_processed = 0;
    static unsigned int current_block = 0;  // Track current block

    // Process available blocks (circular buffer)
    for (unsigned int i = 0; i < tpv3_req.tp_block_nr; ++i) {
        unsigned int block_idx = (current_block + i) % tpv3_req.tp_block_nr;
        struct tpacket_block_desc* block_desc = 
            (struct tpacket_block_desc*)((char*)tpv3_ring_buffer + block_idx * tpv3_req.tp_block_size);

        // Check if block has packets ready for user space
        if (!(block_desc->hdr.bh1.block_status & TP_STATUS_USER)) {
            continue;
        }

        // Process all packets in this block
        // TPACKET_V3 uses variable-length frames, walk through them
        uint8_t* block_start = (uint8_t*)block_desc;
        uint32_t offset = block_desc->hdr.bh1.offset_to_first_pkt;
        uint32_t num_packets = block_desc->hdr.bh1.num_pkts;

        for (uint32_t pkt = 0; pkt < num_packets; ++pkt) {
            struct tpacket3_hdr* frame_hdr = (struct tpacket3_hdr*)(block_start + offset);
            
            // Validate frame header
            if (offset >= tpv3_req.tp_block_size || 
                frame_hdr->tp_next_offset == 0 ||
                frame_hdr->tp_len == 0 || frame_hdr->tp_len > 65536) {
                break;  // Invalid frame, stop processing this block
            }

            // Extract frame data
            uint8_t* frame_data = (uint8_t*)frame_hdr + frame_hdr->tp_mac;
            uint32_t frame_len = frame_hdr->tp_len;

            // Call user callback
            on_frame(frame_data, frame_len);
            packets_processed++;

            // Move to next frame
            offset += frame_hdr->tp_next_offset;
            
            // Break if this was the last frame
            if (pkt == num_packets - 1) {
                break;
            }
        }

        // Mark block as processed and move to next
        block_desc->hdr.bh1.block_status = TP_STATUS_KERNEL;
        current_block = (block_idx + 1) % tpv3_req.tp_block_nr;
        
        // Only process one block per call to avoid blocking
        break;
    }

    return packets_processed;
}

void tpv3_close(void) {
    if (tpv3_ring_buffer && tpv3_ring_buffer != MAP_FAILED) {
        munmap(tpv3_ring_buffer, tpv3_req.tp_block_size * tpv3_req.tp_block_nr);
        tpv3_ring_buffer = nullptr;
    }

    if (tpv3_socket >= 0) {
        close(tpv3_socket);
        tpv3_socket = -1;
    }

    std::cout << "TPACKET_V3 capture closed" << std::endl;
}
