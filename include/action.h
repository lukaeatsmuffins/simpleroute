#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/**
 * Minimal rule-based action system for packet processing
 * 
 * This module provides a simple rule engine for matching packets
 * and applying actions based on protocol fields.
 */

// Action types
typedef enum {
    ACTION_PRINT,   // Print packet details
    ACTION_DROP,    // Drop packet (ignore)
    ACTION_FORWARD  // Forward packet (future use)
} ActionType;

// Protocol types
typedef enum {
    PROTO_ANY = 0,  // Match any protocol
    PROTO_IPV4,     // IPv4 only
    PROTO_IPV6,     // IPv6 only
    PROTO_TCP,      // TCP only
    PROTO_UDP       // UDP only
} ProtocolType;

// Rule structure for packet matching
typedef struct {
    ProtocolType l3_proto;     // L3 protocol (IPv4/IPv6/ANY)
    ProtocolType l4_proto;     // L4 protocol (TCP/UDP/ANY)
    uint16_t dst_port;         // Destination port (0 = any)
    bool dst_port_set;         // Whether dst_port is specified
    ActionType action;         // Action to take
} Rule;

/**
 * Parse a rule expression string into a Rule structure
 * @param expr Rule expression (e.g., "proto=udp,dport=53,action=DROP")
 * @param out Output Rule structure to fill
 * @return 0 on success, negative on error
 */
int rule_parse(const char* expr, Rule* out);

/**
 * Decide what action to take for a parsed packet based on rules
 * @param rule Rule to apply
 * @param parsed Parsed packet structure
 * @return Action to take
 */
ActionType decide(const Rule* rule, const void* parsed);

/**
 * Print a rule in human-readable format
 * @param rule Rule to print
 */
void rule_print(const Rule* rule);

#ifdef __cplusplus
}
#endif
