#pragma once

#include <string>

/**
 * Sniff packets from a network interface using AF_PACKET raw sockets
 * @param interface_name The name of the interface to bind to (e.g., "eth0", "veth1")
 * @return 0 on success, -1 on error
 */
int sniff_packets(const std::string& interface_name);
