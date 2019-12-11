#include "router_hal.h"
#include "rip.h"
#include "router.h"
#include "utils.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <vector>
#define  N_NODE
#define  N_NEIGHBOR

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern uint16_t valSum(const uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);
extern std::vector<RoutingTableEntry> routing_table;

uint8_t packet[2048];
uint8_t output[2048];
// 0: 10.0.0.1  (-> R1)
// 1: 10.0.1.1  (-> R3)
// 2: 10.0.2.1  (not used)
// 3: 10.0.3.1  (not used)
// 你可以按需进行修改，注意端序
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0100000a, 0x0101000a, 0x0102000a, 0x0103000a};
// 组播地址： 224.0.0.9
const in_addr_t MULTICAST_ADDR = 0x90000e0;

int main(int argc, char *argv[]) {
  // 0a. 初始化 HAL，打开调试信息
  int res = HAL_Init(1, addrs); 
  if (res < 0) {
    return res;
  }
  
  // 0b. 创建若干条 /24 直连路由
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
    RoutingTableEntry entry = {
      .addr = addrs[i],
      .len = 24,
      .if_index = i,
      .nexthop = 0, // means direct
      .metric = 1 // 0 or 1 ?
    };
    update(true, entry);
  }

  uint64_t last_time = 0;
  while (1) {
    // 获取当前时间，处理定时任务
    uint64_t time = HAL_GetTicks();
    if (time > last_time + 30 * 1000) {
      // 每 30s 做什么
      // 例如：超时？发 RIP Request/Response
      printf("Timer\n");
      last_time = time;

      // multicast response to all neighbors:
      RipPacket rip;
      // fill resp with all route entries:
      int idx_in_rt = 0;
      do {
        uint32_t entries_to_send = routing_table.size() - idx_in_rt;
        rip.numEntries = std::min(entries_to_send, (uint32_t)RIP_MAX_ENTRY);
        rip.command = CMD_RESPONSE;
        for (int i = 0; i < rip.numEntries; ++i) {
          rip.entries[i] = rtEntry2RipEntry(routing_table.at(idx_in_rt + i)); // TODO use [i]
        }
        // assemble rip packet
        uint32_t rip_len = assemble(&rip, &output[20 + 8]);
        // multicast through all ifs
        for (int if_index = 0; if_index < N_IFACE_ON_BOARD; ++if_index) {
          // assemble ip & udp head
          uint32_t tot_len = writeIpUdpHead(output, rip_len, addrs[if_index], MULTICAST_ADDR);
          macaddr_t multicast_mac;
          res = HAL_ArpGetMacAddress(if_index, MULTICAST_ADDR, multicast_mac);
          assert(res == 0);
          res = HAL_SendIPPacket(if_index, output, tot_len, multicast_mac);
          printf("ifid = %u, res = %d\n", if_index, res);
          assert(res == 0);
        }
        idx_in_rt += rip.numEntries;
      } while (idx_in_rt < routing_table.size()); // possibly send multiple times
      printf("multicast done.\n");
    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1; // listen for all interfaces
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;

    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac, dst_mac, 1000, &if_index);
    if (res == HAL_ERR_EOF) {
      printf("EOF\n");
      break;
    } else if (res < 0) {
      printf("listen: error\n");
      return res;
    } else if (res == 0) {
      printf("listen: timeout\n");
      continue;
    } else if (res > sizeof(packet)) {
      // packet is truncated, ignore it
      printf("listen: truncated\n");
      continue;
    }
    // res > 0: ok

    if (!validateIPChecksum(packet, res)) {
      printf("Invalid IP Checksum\n");
      continue;
    }
    in_addr_t src_addr, dst_addr;
    // extract src_addr and dst_addr from packet
    src_addr = packet[12] + (packet[13] << 8) + (packet[14] << 16) + (packet[15] << 24); // big
    dst_addr = packet[16] + (packet[17] << 8) + (packet[18] << 16) + (packet[19] << 24); // big

    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD;i++) {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
        dst_is_me = true;
        break;
      }
    }
    // Handle rip multicast address?
    if (dst_addr == MULTICAST_ADDR) {
      dst_is_me = true;
    }

    if (dst_is_me) {
      // TODO: RIP?
      RipPacket rip;
      if (disassemble(packet, res, &rip)) {
        if (rip.command == CMD_REQUEST) {
          // responde to request
          RipPacket resp;
          // fill resp with all route entries
          int idx_in_rt = 0;
          do {
            uint32_t entries_to_send = routing_table.size() - idx_in_rt;
            resp.numEntries = std::min(entries_to_send, (uint32_t)RIP_MAX_ENTRY);
            resp.command = CMD_RESPONSE;
            for (int i = 0; i < resp.numEntries; ++i) {
              resp.entries[i] = rtEntry2RipEntry(routing_table.at(idx_in_rt + i)); // TODO use [i]
            }
            // assemble rip packet
            uint32_t rip_len = assemble(&rip, &output[20 + 8]);
            // assemble ip & udp head
            uint32_t tot_len = writeIpUdpHead(output, rip_len, dst_addr, src_addr);
            // send it back
            res = HAL_SendIPPacket(if_index, output, tot_len, src_mac);
            assert(res == 0);

            idx_in_rt += resp.numEntries;
          } while (idx_in_rt < routing_table.size()); // possibly send multiple times
        } else {
          // response
          // TODO: use query and update
        }
      } else {
        // forward
        // beware of endianness
        uint32_t nexthop, dest_if;
        if (query(src_addr, &nexthop, &dest_if)) {
          // found
          macaddr_t dest_mac;
          // direct routing
          if (nexthop == 0) {
            nexthop = dst_addr;
          }
          if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
            // found
            memcpy(output, packet, res);
            // update ttl and checksum
            forward(output, res);
            // TODO: you might want to check ttl=0 case
            HAL_SendIPPacket(dest_if, output, res, dest_mac);
          } else {
            // not found
          }
        } else {
          // not found
        }
      }
    }
  }
  return 0;
}
