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
    int frames_per_block = tpv3_req.tp_block_size / tpv3_req.tp_frame_size;

    // Process all available blocks
    for (unsigned int block = 0; block < tpv3_req.tp_block_nr; ++block) {
        struct tpacket_block_desc* block_desc = 
            (struct tpacket_block_desc*)((char*)tpv3_ring_buffer + block * tpv3_req.tp_block_size);

        // Check if block has packets ready for user space
        if (!(block_desc->hdr.bh1.block_status & TP_STATUS_USER)) {
            continue;
        }

        // Process all frames in this block
        for (int frame = 0; frame < frames_per_block; ++frame) {
            struct tpacket3_hdr* frame_hdr = 
                (struct tpacket3_hdr*)((char*)block_desc + frame * tpv3_req.tp_frame_size);

            // Check if frame has data
            if (frame_hdr->tp_status & TP_STATUS_USER) {
                uint8_t* frame_data = (uint8_t*)frame_hdr + frame_hdr->tp_mac;
                uint32_t frame_len = frame_hdr->tp_len;
                
                // Sanity check for frame length
                if (frame_len > 65536 || frame_len == 0) {  // Reasonable max packet size
                    continue;  // Skip invalid frames
                }

                // Call user callback
                on_frame(frame_data, frame_len);
                packets_processed++;

                // Mark frame as processed
                frame_hdr->tp_status = TP_STATUS_KERNEL;
            }
        }

        // Mark block as processed
        block_desc->hdr.bh1.block_status = TP_STATUS_KERNEL;
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
