# AFP - Simple AF_PACKET Router: A User-Space Packet Processing Implementation

## 1. Introduction

This section will introduce the motivation and objectives of implementing a user-space packet processing application using Linux AF_PACKET sockets. The introduction will establish the context of modern network processing challenges, explain why user-space solutions are increasingly important in network function virtualization and software-defined networking, and outline the specific goals of creating a minimal yet functional packet router. The section will also present the thesis structure and summarize the key contributions of this work, including the demonstration of AF_PACKET socket capabilities, implementation of different packet capture mechanisms, and development of a rule-based packet processing system.

## 2. Background

This section will provide the theoretical foundation necessary to understand the implementation details and design decisions. It will cover the fundamentals of Linux network stack architecture, explaining how packets flow from network interfaces through the kernel to user-space applications. The discussion will include an overview of AF_PACKET sockets, their advantages over traditional socket types for packet processing, and the differences between SOCK_RAW and SOCK_DGRAM modes. Additionally, this section will explore TPACKET_V3 ring buffers, their zero-copy mechanisms, and performance benefits. The background will also review related work in user-space packet processing frameworks like DPDK, comparing their approaches with the simpler AF_PACKET-based solution implemented in this thesis.

## 3. Design

This section will present the architectural design of the AFP application, detailing the three main operational modes: basic packet sniffing using recvfrom(), advanced capture using TPACKET_V3 ring buffers, and packet forwarding between interfaces. The design discussion will cover the modular structure of the application, explaining how packet parsing, rule matching, and action execution components interact. The section will also describe the rule-based filtering system, including the syntax for specifying protocol filters and actions (PRINT, DROP, FORWARD). Network namespace integration for safe testing will be explained, along with the rationale for using veth pairs to create isolated test environments that prevent accidental network disruption.

## 4. Implementation

This section will provide detailed implementation specifics, including code organization, key algorithms, and technical challenges encountered during development. The implementation discussion will cover the packet parsing logic for Ethernet, IPv4/IPv6, TCP, and UDP headers, explaining how the application handles different protocol combinations and malformed packets. The section will detail the TPACKET_V3 ring buffer management, including memory mapping, block processing, and polling mechanisms. Error handling strategies, capability requirements (CAP_NET_RAW and CAP_NET_ADMIN), and performance considerations will be discussed. The implementation of the rule engine, including parsing rule strings and matching packets against specified criteria, will be thoroughly explained with code examples.

## 5. Demonstration Scenarios

This section will present comprehensive testing scenarios that validate the functionality and performance of the AFP application. The demonstrations will include packet capture scenarios showing the application's ability to process various traffic types (TCP, UDP, ICMP) and apply filtering rules correctly. Forwarding scenarios will demonstrate the application's router-like behavior, including traffic between network namespaces and rule-based packet manipulation. Performance comparisons between the basic recvfrom() mode and TPACKET_V3 mode will be presented, along with packet loss measurements under different traffic loads. The section will also include validation of the network namespace setup scripts and their effectiveness in creating isolated test environments for safe experimentation.

## 6. Limitations

This section will honestly assess the limitations and constraints of the current implementation, providing a balanced view of what the AFP application can and cannot achieve. The discussion will cover performance limitations compared to kernel-based forwarding and specialized frameworks like DPDK, including throughput bottlenecks and latency considerations. The section will address security limitations, explaining why the application is suitable only for controlled environments and not production networks. Protocol support limitations will be discussed, noting which network protocols and features are not currently handled. The scalability constraints of the single-threaded design and rule processing will be analyzed, along with memory usage patterns and potential optimization opportunities.

## 7. Conclusion

This section will synthesize the key findings and contributions of the thesis, summarizing what was learned about AF_PACKET socket programming and user-space packet processing. The conclusion will reflect on the effectiveness of the implemented approach in demonstrating core networking concepts and providing a foundation for more advanced packet processing applications. Future work directions will be outlined, including potential enhancements such as multi-threading support, additional protocol handlers, integration with network monitoring tools, and performance optimizations. The section will conclude with final thoughts on the educational value of implementing network functions in user-space and the role of such implementations in understanding modern network processing architectures.
