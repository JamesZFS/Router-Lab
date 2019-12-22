#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <cstdio>
#include <cstring>

static void printByte(uint8_t a)
{
	auto b = (uint8_t *) (&a);  // low bit at right
	for (int k = 7; k >= 0; --k) {
		printf("%u", (bool) (*b & (1 << k)));
	}
}

static void printPacket(const uint8_t *packet, uint32_t len) {
  for (int i = 0; i < len; ++i)
    printf("%.2x ", packet[i]);
  printf("\n");
}

/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(for response) and 0(for request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

#define MAKE_SURE(cond)  if (!(cond)) return false;

static bool checkMask(uint32_t mask) {
  uint32_t i = 0;
  while (i < 32 && (mask & 1)) {
    mask >>= 1;
    i++;
  }
  while (i++ < 32) {
    if (mask & 1) return false;
    mask >>= 1;
  }
  return true;
}

static uint32_t endianSwap(uint32_t a) {
  return (a >> 24) | ((a & 0x00FF0000) >> 8) | ((a & 0x0000FF00) << 8) | ((a & 0x000000FF) << 24);
}

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系（见上面结构体注释），Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
  const uint32_t ip_hlen = (packet[0] & 0b00001111) * 4;  // in byte
  constexpr uint32_t udp_hlen = 8; // bytes
  constexpr uint32_t ripentry_size = 20; // bytes
  packet += ip_hlen + udp_hlen;  // skip ip head and udp head
  const uint32_t ripentry_tot_size = (len - ip_hlen - udp_hlen - 4);
  MAKE_SURE(ripentry_tot_size % ripentry_size == 0);
  output->numEntries = ripentry_tot_size / ripentry_size; // infer number of entries
  const uint8_t command = packet[0];
  MAKE_SURE(command == CMD_REQUEST || command == CMD_RESPONSE) // check command
  output->command = command;
  MAKE_SURE(packet[1] == RIP_V2); // check version
  MAKE_SURE(packet[2] == 0 && packet[3] == 0); // check zero
  packet += 4; // skip RIPv2 header
  for (auto i = 0; i < output->numEntries; ++i, packet += 20) {
    // parse all RipEntries
    RipEntry &e = output->entries[i];
    MAKE_SURE(packet[0] == 0 && ((packet[1] == 2 && command == CMD_RESPONSE) || (packet[1] == 0 && command == CMD_REQUEST))); // family
    MAKE_SURE(packet[2] == 0 && packet[3] == 0); // tag
    e.addr = packet[4] + (packet[5] << 8) + (packet[6] << 16) + (packet[7] << 24); // big
    // printf("ip addr: %.8x\n", rip_entry.addr);
    e.mask = packet[8] + (packet[9] << 8) + (packet[10] << 16) + (packet[11] << 24); // big
    uint32_t mask_little = endianSwap(e.mask);
    MAKE_SURE(checkMask(e.mask)); // mask should look like (low)'1111000'(high)
    e.addr &= e.mask;
    e.nexthop = packet[12] + (packet[13] << 8) + (packet[14] << 16) + (packet[15] << 24); // big
    e.nexthop &= e.mask;
    uint32_t metric_little = (packet[16] << 24) + (packet[17] << 16) + (packet[18] << 8) + packet[19]; // little
    MAKE_SURE((command == CMD_REQUEST && metric_little == 16) || (command == CMD_RESPONSE && 1 <= metric_little && metric_little <= 16));
    e.metric = packet[16] + (packet[17] << 8) + (packet[18] << 16) + (packet[19] << 24); // big
    // printf("\033[32mass rpe ip: %u.%u.%u.%u\033[0m\n", (uint8_t)e.addr, (uint8_t)(e.addr>>8), (uint8_t)(e.addr>>16), (uint8_t)(e.addr>>24));
  }
  return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
  uint32_t p = 0;
  // rip head
  buffer[p++] = rip->command;
  buffer[p++] = 2; // RIPv2 version
  buffer[p++] = 0;
  buffer[p++] = 0; // zero
  for (uint32_t i = 0; i < rip->numEntries; ++i) {
    const RipEntry &e = rip->entries[i];
    // family
    buffer[p++] = 0;
    buffer[p++] = rip->command == CMD_RESPONSE ? 2 : 0;
    // tag
    buffer[p++] = 0;
    buffer[p++] = 0;
    // ip
    memcpy(&buffer[p], &e.addr, sizeof(e.addr));
    p += 4;
    // mask
    memcpy(&buffer[p], &e.mask, sizeof(e.mask));
    p += 4;
    // hop
    memcpy(&buffer[p], &e.nexthop, sizeof(e.nexthop));
    p += 4;
    // metric
    memcpy(&buffer[p], &e.metric, sizeof(e.metric));
    p += 4;
  }
  return p;
}
