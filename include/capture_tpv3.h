#pragma once

#include <stdint.h>

/**
 * TPACKET_V3-based packet capture using mmap() and ring buffers
 * 
 * This module provides high-performance packet capture using Linux's TPACKET_V3
 * mechanism with memory-mapped ring buffers for zero-copy packet processing.
 */

/**
 * Open TPACKET_V3 capture on the specified interface
 * @param ifname Interface name (e.g., "eth0", "veth1")
 * @return 0 on success, -1 on error
 */
int tpv3_open(const char* ifname);

/**
 * Poll for new packets in the ring buffer
 * @param timeout_ms Timeout in milliseconds (0 = non-blocking, -1 = blocking)
 * @return Number of packets available, -1 on error
 */
int tpv3_poll(int timeout_ms);

/**
 * Process next available packet(s) in the ring buffer
 * @param on_frame Callback function called for each packet
 * @return Number of packets processed, -1 on error
 */
int tpv3_next(void (*on_frame)(const uint8_t* frame, uint32_t len));

/**
 * Close TPACKET_V3 capture and cleanup resources
 */
void tpv3_close(void);
