#include "router_hal.h"
#include "rip.h"
#include "router.h"
#include "utils.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

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
    .metric = e.metric
  };
}

// RoutingTableEntry RipEntry2rtEntry(const RipEntry &e) {
//   return RoutingTableEntry{
//     .addr = e.addr,
//     .
//   }
// }

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
  // buffer[10], buffer[11]: checksum
  memcpy(&buffer[12], &src_addr, sizeof(src_addr)); // src ip
  memcpy(&buffer[16], &dst_addr, sizeof(dst_addr)); // dst_ip
  uint16_t checksum = valSum(buffer, 20);
  buffer[10] = (uint8_t)(checksum >> 8), buffer[11] = (uint8_t)checksum; // checksum
  // UDP
  // port = 520
  buffer[20] = 0x02;
  buffer[21] = 0x08;
  
  return tot_len;
}
