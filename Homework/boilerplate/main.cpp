#include "router_hal.h"
#include "rip.h"
#include "router.h"
#include "utils.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <algorithm>
#include <vector> 

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern uint16_t valSum(const uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
// extern bool forward(uint8_t *packet, size_t len);
bool forwardFast(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);
extern uint32_t countTrailingOne(uint32_t a);
extern uint32_t endianSwap(uint32_t a);
extern std::vector<RoutingTableEntry>::iterator find(const RoutingTableEntry &entry);
extern std::vector<RoutingTableEntry> routing_table;

uint8_t packet[2048];
uint8_t output[2048];

// 你可以按需进行修改，注意端序

// R2:
// 0: 192.168.3.2  (-> R1)
// 1: 192.168.4.1  (-> R3)
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0203a8c0, 0x0104a8c0};

// R1:
// 0: 192.168.3.1  (-> R2)
// 1: 192.168.1.1  (-> PC1)
// in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0103a8c0, 0x0101a8c0};
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
      .addr = addrs[i] & 0x00ffffff,
      .len = 24,
      .if_index = i,
      .nexthop = 0, // means direct
      .metric = 1
    };
    update(true, entry);
  }

  uint64_t last_time = 0;
  while (1) {
    // 获取当前时间，处理定时任务
    uint64_t time = HAL_GetTicks();
    if (time > last_time + 5 * 1000) {
      // 每 30s 做什么
      // 例如：超时？发 RIP Request/Response
      printf("\033[33mTimer Event\033[0m\n");
      last_time = time;

      // multicast response to all neighbors:
      RipPacket rip;
      for (int if_index = 0; if_index < N_IFACE_ON_BOARD; ++if_index) {
        // fill resp with all route entries:
        int idx_in_rt = 0;
        do {
          rip.command = CMD_RESPONSE;
          uint32_t entries_to_send = routing_table.size() - idx_in_rt;
          entries_to_send = std::min(entries_to_send, (uint32_t)RIP_MAX_ENTRY);
          rip.numEntries = 0;
          for (int i = 0; i < entries_to_send; ++i) {
            const RoutingTableEntry &rte = routing_table.at(idx_in_rt + i);
            if (rte.if_index == if_index) continue; // TODO nexthop | addr
            rip.entries[rip.numEntries++] = rtEntry2RipEntry(rte);
          }
          // assemble rip packet
          uint32_t rip_len = assemble(&rip, &output[20 + 8]);
          // multicast through all ifs
          
          // assemble ip & udp head
          uint32_t tot_len = writeIpUdpHead(output, rip_len, addrs[if_index], MULTICAST_ADDR);
          macaddr_t multicast_mac;
          res = HAL_ArpGetMacAddress(if_index, MULTICAST_ADDR, multicast_mac);
          assert(res == 0);
          res = HAL_SendIPPacket(if_index, output, tot_len, multicast_mac);
          printf("if_id = %u, res = %d, idx_in_rt = %d\n", if_index, res, idx_in_rt);
          assert(res == 0);
          
          idx_in_rt += entries_to_send;
        } while (idx_in_rt < routing_table.size()); // possibly send multiple times
      } // for if_index
      printf("multicast done.\n");
      printRoutingTable();
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
    auto packet_len = res;
    // 1. 检查是否是合法的 IP 包，可以用你编写的 validateIPChecksum 函数，还需要一些额外的检查
    if (!validateIPChecksum(packet, packet_len)) {
      printf("\033[31mInvalid IP Checksum\033[0m\n");
      continue;
    }
    in_addr_t src_addr, dst_addr;
    // extract src_addr and dst_addr from packet
    src_addr = packet[12] + (packet[13] << 8) + (packet[14] << 16) + (packet[15] << 24); // big
    dst_addr = packet[16] + (packet[17] << 8) + (packet[18] << 16) + (packet[19] << 24); // big
    printf("learned an IP packet, src: %u.%u.%u.%u  dst: %u.%u.%u.%u\n", 
          packet[12], packet[13], packet[14], packet[15], 
          packet[16], packet[17], packet[18], packet[19]);

    // 2. 检查目的地址，如果是路由器自己的 IP（或者是 RIP 的组播地址），进入 3a；否则进入 3b
    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD;i++) {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
        dst_is_me = true;
        break;
      }
    }
    // Handle rip multicast address?
    if (dst_addr == MULTICAST_ADDR) {
      printf("received multicast!\n");
      dst_is_me = true;
    }

    if (dst_is_me) { // 3a
      printf("dst is me\n");
      RipPacket rip;
      // is this packet a RIP?
      if (disassemble(packet, packet_len, &rip)) {
        if (rip.command == CMD_REQUEST) {
          // 3a.3 如果是 Request 包，就遍历本地的路由表，构造出一个 RipPacket 结构体，
          //      然后调用你编写的 assemble 函数，另外再把 IP 和 UDP 头补充在前面，
          //      通过 HAL_SendIPPacket 发回询问的网口
          RipPacket resp;
          // fill resp with all route entries
          int idx_in_rt = 0;
          do {
            uint32_t entries_to_send = routing_table.size() - idx_in_rt;
            resp.numEntries = std::min(entries_to_send, (uint32_t)RIP_MAX_ENTRY);
            resp.command = CMD_RESPONSE;
            for (int i = 0; i < resp.numEntries; ++i) {
              resp.entries[i] = rtEntry2RipEntry(routing_table[idx_in_rt + i]); // TODO use [i]
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
          // 3a.2 如果是 Response 包，就调用你编写的 query 和 update 函数进行查询和更新，
          //      注意此时的 RoutingTableEntry 可能要添加新的字段（如metric、timestamp），
          //      如果有路由更新的情况，可能需要构造出 RipPacket 结构体，调用你编写的 assemble 函数，
          //      再把 IP 和 UDP 头补充在前面，通过 HAL_SendIPPacket 把它发到别的网口上
          // use query and update

          printf("got response packet\n");
          bool did_update_rt = false;
          for (int i = 0; i < rip.numEntries; ++i) {
            const RipEntry &rpe = rip.entries[i];
            // printf("\033[31mrpe ip: %u.%u.%u.%u\033[0m\n", (uint8_t)rpe.addr, (uint8_t)(rpe.addr>>8), (uint8_t)(rpe.addr>>16), (uint8_t)(rpe.addr>>24));
            uint8_t metric = (uint8_t)endianSwap(rpe.metric);
            if (metric + 1 > 16) {
              // deleting this route entry ?
              bool is_direct = false;
              for (int i = 0; i < N_IFACE_ON_BOARD; ++i) {
                if ((rpe.addr & rpe.mask) == (addrs[i] & 0x00ffffff)) {
                  is_direct = true;
                  break;
                }
              }
              if (is_direct) {
                printf("protect direct routing\n");
                continue; // protect direct routing
              }
              auto rte = RipEntry2rtEntry(rpe);
              auto where = find(rte);
              if (where == routing_table.end()) {
                printf("Fail to delete in routing table, the entry is not found.");
                printf("ip: %u.%u.%u.%u/%u \n", (uint8_t)rte.addr, (uint8_t)(rte.addr>>8), (uint8_t)(rte.addr>>16), (uint8_t)(rte.addr>>24), rte.len);
                continue;
              }
              if (where->if_index != if_index) {
                printf("protect route entry for if_index not match\n");
                continue;
              }
              printf("\033[32mdeleting route entry: \033[0m");
              printf("%u.%u.%u.%u/%u \n", (uint8_t)rte.addr, (uint8_t)(rte.addr>>8), (uint8_t)(rte.addr>>16), (uint8_t)(rte.addr>>24), rte.len);
              did_update_rt = true;
              routing_table.erase(where);
              RipPacket resp; // construct expire packet
              resp.command = CMD_RESPONSE;
              resp.numEntries = 1;
              resp.entries[0] = rpe;
              auto rip_len = assemble(&resp, &output[20 + 8]);
              // multicast expire packet to all if except in_if
              for (int out_if = 0; out_if < N_IFACE_ON_BOARD; ++out_if) {
                if (out_if == if_index) continue; // avoid sending back
                auto tot_len = writeIpUdpHead(output, rip_len, addrs[out_if], MULTICAST_ADDR);
                macaddr_t multicast_mac;
                res = HAL_ArpGetMacAddress(out_if, MULTICAST_ADDR, multicast_mac);
                assert(res == 0);
                res = HAL_SendIPPacket(out_if, output, tot_len, multicast_mac);
                assert(res == 0);
                printf("expire packet sent to %d\n", out_if);
              }
            } else {
              // insert / update?
              RoutingTableEntry rte = {
                .addr = rpe.addr,
                .len = countTrailingOne(rpe.mask),
                .if_index = (uint32_t)if_index,
                .nexthop = src_addr,
                .metric = (uint8_t)(endianSwap(rpe.metric) + 1u)
              };
              auto where = find(rte);
              if (where == routing_table.end()) {
                // not found, insert
                did_update_rt = true;
                printf("\033[32minserting route entry: \033[0m");
                printf("%u.%u.%u.%u/%u \n", (uint8_t)rte.addr, (uint8_t)(rte.addr>>8), (uint8_t)(rte.addr>>16), (uint8_t)(rte.addr>>24), rte.len);
                routing_table.push_back(rte);
              } else {
                // found the same route
                if (metric + 1 <= where->metric) {
                  // update
                  did_update_rt = true;
                  printf("\033[32mupdating route entry: \033[0m");
                  printf("%u.%u.%u.%u/%u \n", (uint8_t)rte.addr, (uint8_t)(rte.addr>>8), (uint8_t)(rte.addr>>16), (uint8_t)(rte.addr>>24), rte.len);
                  *where = rte;
                  // wait until next periodical multicast
                  // or incrementally multicast now
                }
                // else: no op
              }
            }
          }
          if (did_update_rt) {
            printf("\033[32mupdated routing table\n");
            printRoutingTable();
            printf("\033[0m");
          }
        }
      } else { // if not a valid rip, ignore
        printf("not a valid rip\n");
      }
    } else {
      printf("forwarding\n");
      // 3b.1 此时目的 IP 地址不是路由器本身，则调用你编写的 query 函数查询，
      //      如果查到目的地址，如果是直连路由， nexthop 改为目的 IP 地址，
      //      用 HAL_ArpGetMacAddress 获取 nexthop 的 MAC 地址，
      // beware of endianness
      uint32_t nexthop, dest_if;
      if (query(dst_addr, &nexthop, &dest_if)) {
        // found
        macaddr_t dest_mac;
        // direct routing
        if (nexthop == 0) {
          nexthop = dst_addr;
        }
        if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
          // 如果找到了，就调用你编写的 forward 函数进行 TTL 和 Checksum 的更新，
          // 通过 HAL_SendIPPacket 发到指定的网口，
          // 在 TTL 减到 0 的时候建议构造一个 ICMP Time Exceeded 返回给发送者；
          memcpy(output, packet, packet_len);
          // update ttl and checksum
          if (!forwardFast(output, packet_len)) {
            printf("forwarding checksum failed.\n");
            break;
          }
          if (packet[8] == 0) { // if ttl == 0
            // TODO: send a ICMP Time Exceeded to sender
            printf("ICMP TllE\n");
          } else {
            res = HAL_SendIPPacket(dest_if, output, packet_len, dest_mac);
            assert(res == 0);
            printf("forwarded.\n");
          }
        } else {
          // 如果没查到下一跳的 MAC 地址，HAL 会自动发出 ARP 请求，在对方回复后，下次转发时就知道了
        }
      } else {
        // TODO not found
        // 如果没查到目的地址的路由，建议返回一个 ICMP Destination Network Unreachable
        // printf("ICMP Destination Network Unreachable\n");
      } // query

    } // if dst_is_me

  } // while 1

  return 0;
} // main
