#include "action.h"
#include "parse.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <arpa/inet.h>

// Helper function to skip whitespace
static const char* skip_whitespace(const char* str) {
    while (*str && isspace(*str)) {
        str++;
    }
    return str;
}

// Helper function to parse protocol string (case-insensitive)
static ProtocolType parse_protocol(const char* proto_str) {
    if (strcasecmp(proto_str, "ipv4") == 0) {
        return PROTO_IPV4;
    } else if (strcasecmp(proto_str, "ipv6") == 0) {
        return PROTO_IPV6;
    } else if (strcasecmp(proto_str, "tcp") == 0) {
        return PROTO_TCP;
    } else if (strcasecmp(proto_str, "udp") == 0) {
        return PROTO_UDP;
    } else if (strcasecmp(proto_str, "any") == 0) {
        return PROTO_ANY;
    }
    return PROTO_ANY;  // Default to any
}

// Helper function to parse action string (case-insensitive)
static ActionType parse_action(const char* action_str) {
    if (strcasecmp(action_str, "print") == 0) {
        return ACTION_PRINT;
    } else if (strcasecmp(action_str, "drop") == 0) {
        return ACTION_DROP;
    } else if (strcasecmp(action_str, "forward") == 0) {
        return ACTION_FORWARD;
    }
    return ACTION_PRINT;  // Default to print
}

int rule_parse(const char* expr, Rule* out) {
    if (!expr || !out) {
        return -1;
    }
    
    // Initialize rule with defaults
    memset(out, 0, sizeof(Rule));
    out->l3_proto = PROTO_ANY;
    out->l4_proto = PROTO_ANY;
    out->dst_port = 0;
    out->dst_port_set = false;
    out->action = ACTION_PRINT;
    
    // Parse comma-separated key=value pairs
    const char* pos = expr;
    while (*pos) {
        pos = skip_whitespace(pos);
        if (!*pos) break;
        
        // Find the end of current key=value pair
        const char* comma = strchr(pos, ',');
        const char* end = comma ? comma : pos + strlen(pos);
        
        // Find the equals sign
        const char* equals = strchr(pos, '=');
        if (!equals || equals >= end) {
            return -2;  // Invalid format
        }
        
        // Extract key and value
        size_t key_len = equals - pos;
        size_t value_len = end - equals - 1;
        
        char key[32], value[32];
        if (key_len >= sizeof(key) || value_len >= sizeof(value)) {
            return -3;  // Key or value too long
        }
        
        strncpy(key, pos, key_len);
        key[key_len] = '\0';
        strncpy(value, equals + 1, value_len);
        value[value_len] = '\0';
        
        // Remove trailing whitespace from key
        while (key_len > 0 && isspace(key[key_len - 1])) {
            key[--key_len] = '\0';
        }
        
        // Remove leading/trailing whitespace from value
        const char* value_start = value;
        while (*value_start && isspace(*value_start)) {
            value_start++;
        }
        const char* value_end = value + strlen(value);
        while (value_end > value_start && isspace(value_end[-1])) {
            value_end--;
        }
        size_t clean_value_len = value_end - value_start;
        if (clean_value_len >= sizeof(value)) {
            return -4;  // Cleaned value too long
        }
        memmove(value, value_start, clean_value_len);
        value[clean_value_len] = '\0';
        
        // Parse based on key
        if (strcmp(key, "proto") == 0) {
            ProtocolType proto = parse_protocol(value);
            if (proto == PROTO_TCP || proto == PROTO_UDP) {
                out->l4_proto = proto;
            } else if (proto == PROTO_IPV4 || proto == PROTO_IPV6) {
                out->l3_proto = proto;
            } else {
                return -5;  // Invalid protocol
            }
        } else if (strcmp(key, "l3proto") == 0) {
            out->l3_proto = parse_protocol(value);
        } else if (strcmp(key, "l4proto") == 0) {
            out->l4_proto = parse_protocol(value);
        } else if (strcmp(key, "dport") == 0) {
            char* endptr;
            long port = strtol(value, &endptr, 10);
            if (*endptr != '\0' || port < 0 || port > 65535) {
                return -6;  // Invalid port number
            }
            out->dst_port = (uint16_t)port;
            out->dst_port_set = true;
        } else if (strcmp(key, "action") == 0) {
            out->action = parse_action(value);
        } else {
            return -7;  // Unknown key
        }
        
        // Move to next pair
        pos = comma ? comma + 1 : end;
    }
    
    return 0;  // Success
}

ActionType decide(const Rule* rule, const void* parsed) {
    if (!rule || !parsed) {
        return ACTION_PRINT;  // Default action
    }
    
    const Parsed* p = static_cast<const Parsed*>(parsed);
    
    // Check L3 protocol match
    if (rule->l3_proto != PROTO_ANY) {
        if (rule->l3_proto == PROTO_IPV4 && !p->has_ipv4) {
            return ACTION_PRINT;  // No match, default action
        }
        if (rule->l3_proto == PROTO_IPV6 && !p->has_ipv6) {
            return ACTION_PRINT;  // No match, default action
        }
    }
    
    // Check L4 protocol match
    if (rule->l4_proto != PROTO_ANY) {
        if (rule->l4_proto == PROTO_TCP && !p->has_tcp) {
            return ACTION_PRINT;  // No match, default action
        }
        if (rule->l4_proto == PROTO_UDP && !p->has_udp) {
            return ACTION_PRINT;  // No match, default action
        }
    }
    
    // Check destination port match
    if (rule->dst_port_set) {
        uint16_t packet_dport = 0;
        if (p->has_tcp) {
            packet_dport = ntohs(p->tcp.dst_port);
        } else if (p->has_udp) {
            packet_dport = ntohs(p->udp.dst_port);
        } else {
            return ACTION_PRINT;  // No transport layer, default action
        }
        
        if (packet_dport != rule->dst_port) {
            return ACTION_PRINT;  // Port doesn't match, default action
        }
    }
    
    // All conditions matched, return rule action
    return rule->action;
}

void rule_print(const Rule* rule) {
    if (!rule) {
        printf("(null rule)\n");
        return;
    }
    
    printf("Rule: ");
    
    // L3 protocol
    if (rule->l3_proto != PROTO_ANY) {
        const char* proto_str = (rule->l3_proto == PROTO_IPV4) ? "IPv4" : "IPv6";
        printf("l3proto=%s ", proto_str);
    }
    
    // L4 protocol
    if (rule->l4_proto != PROTO_ANY) {
        const char* proto_str = (rule->l4_proto == PROTO_TCP) ? "TCP" : "UDP";
        printf("l4proto=%s ", proto_str);
    }
    
    // Destination port
    if (rule->dst_port_set) {
        printf("dport=%d ", rule->dst_port);
    }
    
    // Action
    const char* action_str = "PRINT";
    if (rule->action == ACTION_DROP) {
        action_str = "DROP";
    } else if (rule->action == ACTION_FORWARD) {
        action_str = "FORWARD";
    }
    printf("action=%s", action_str);
    
    printf("\n");
}
