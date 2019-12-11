#ifndef _UTILS_H
#define _UTILS_H

RipEntry rtEntry2RipEntry(const RoutingTableEntry &e);
uint32_t endianSwap(uint32_t a);
uint32_t writeIpUdpHead(uint8_t *buffer, uint32_t body_len, uint32_t src_addr, uint32_t dst_addr);

#endif