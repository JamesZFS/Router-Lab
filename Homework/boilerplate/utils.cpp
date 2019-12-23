#include "utils.h"
#include "router_hal.h"
#include "router.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <vector>

static uint16_t valSum(const uint8_t *packet, size_t len) {
  uint32_t sum = 0;
  uint32_t overflow = 0;
  for (size_t i = 0; i < len; i += 2) { // step 2 uint_8s
    sum += (packet[i] << 8) + packet[i+1];
    do {
      overflow = (sum & 0xFFFF0000) >> 16; // take hi 16 bits of sum
      sum &= 0x0000FFFF;  // trunc to lo 16 bits
      sum += overflow;
    } while (overflow != 0);
  }
  sum = ~sum & 0x0000FFFF; // logical not

  return sum;
}

RipEntry rtEntry2RipEntry(const RoutingTableEntry &e) {
  return RipEntry{
    .addr = e.addr,
    .mask = (0x1u << e.len) - 1u, // caution!
    .nexthop = e.nexthop,
    .metric = endianSwap(e.metric)
  };
}

uint32_t countLeadingOne(uint32_t a) {
  uint32_t len;
  for (len = 0; len < 32; ++len) {
    if ((a & 0x01) == 1) { // count trailing zero
      break;
    }
    a >>= 1;
  }
  return 32 - len;
}

RoutingTableEntry RipEntry2rtEntry(const RipEntry &e) {
  return RoutingTableEntry{
    .addr = e.addr,
    .len = countLeadingOne(endianSwap(e.mask)),
    .if_index = 0,  // uninitialized
    .nexthop = e.nexthop,
    .metric = (uint8_t)endianSwap(e.metric)
  };
}

uint32_t endianSwap(uint32_t a) {
  return (a >> 24) | ((a & 0x00FF0000) >> 8) | ((a & 0x0000FF00) << 8) | ((a & 0x000000FF) << 24);
}

// assuming the `buffer`'s body has already been assembled, return the total len = head + body
uint32_t writeIpUdpHead(uint8_t *buffer, uint32_t body_len, uint32_t src_addr, uint32_t dst_addr) {
  /**
   * 代码中在发送 RIP 包的时候，会涉及到 IP 头的构造，由于不需要用各种高级特性，
   * 可以这么设定：V=4，IHL=5，TOS(DSCP/ECN)=0，ID=0，FLAGS/OFF=0，
   * TTL=1，其余按照要求实现即可。
   */
  uint16_t tot_len = body_len + 20 + 8; // 20 for ip, 8 for udp
  buffer[0] = 0x45;
  buffer[1] = 0xC0;
  buffer[2] = (uint8_t)(tot_len >> 8), buffer[3] = (uint8_t)tot_len; // total length
  buffer[4] = 0, buffer[5] = 0; // identification
  buffer[6] = 0x40, buffer[7] = 0; // fragment
  buffer[8] = 1; // TTL
  buffer[9] = 0x11; // protocol: udp
  buffer[10] = 0, buffer[11] = 0; // checksum
  memcpy(&buffer[12], &src_addr, sizeof(src_addr)); // src ip
  memcpy(&buffer[16], &dst_addr, sizeof(dst_addr)); // dst_ip
  uint16_t checksum = valSum(buffer, 20);
  buffer[10] = (uint8_t)(checksum >> 8), buffer[11] = (uint8_t)checksum; // checksum
  // UDP
  // port = 520
  buffer[20] = 0x02, buffer[21] = 0x08; // src 520
  buffer[22] = 0x02, buffer[23] = 0x08; // dst 520
  buffer[24] = (uint8_t)((8 + body_len)>>8), buffer[25] = (uint8_t)(8 + body_len); // length
  // checksum = valSum(&buffer[20], 8);
  // buffer[26] = (uint8_t)(checksum >> 8), buffer[27] = (uint8_t)checksum; // checksum
  buffer[26] = 0, buffer[27] = 0; // checksum
  
  return tot_len;
}

extern std::vector<RoutingTableEntry> routing_table;

void printRoutingTable() {
  printf("=== current routing table ===\n");
  for (const RoutingTableEntry &e : routing_table) {
    printf("\tip: %u.%u.%u.%u/%u  ", (uint8_t)e.addr, (uint8_t)(e.addr>>8), (uint8_t)(e.addr>>16), (uint8_t)(e.addr>>24), e.len);
    printf("if: %u  ", e.if_index);
    printf("nexthop: %u.%u.%u.%u  ", (uint8_t)e.nexthop, (uint8_t)(e.nexthop>>8), (uint8_t)(e.nexthop>>16), (uint8_t)(e.nexthop>>24));
    printf("metric: %u\n", e.metric);
  }
}

// // return length of icmp body
// uint32_t writeIcmpTllE(uint8_t *buffer) { // Tll exceed
//     buffer[0] = 11; // type
//     buffer[1] = 0; // code
//     // valSum
// }
