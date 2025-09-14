#pragma once

#include <stdint.h>

/**
 * Raw packet transmitter for mirror-style forwarding
 * 
 * This module provides raw socket-based packet transmission for controlled
 * demos and testing scenarios (e.g., veth pairs). It performs simple
 * mirror-style forwarding without modifying MAC addresses or implementing ARP.
 * 
 * WARNING: This is intended for controlled environments only. Do not use
 * on production networks without proper safeguards.
 */

/**
 * Open raw socket transmitter bound to the specified interface
 * @param ifname Interface name to bind to (e.g., "eth0", "veth1")
 * @return 0 on success, -1 on error
 */
int tx_open(const char* ifname);

/**
 * Send a raw frame through the transmitter
 * @param frame Raw frame data (starting from Ethernet header)
 * @param len Length of the frame data
 * @return Number of bytes sent on success, -1 on error
 */
int tx_send(const uint8_t* frame, uint32_t len);

/**
 * Close the transmitter and cleanup resources
 */
void tx_close(void);
