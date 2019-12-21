#include <stdint.h>
#include <stdlib.h>
#include <cstdio>

static void printByte(uint8_t a)
{
	auto b = (uint8_t *) (&a);  // low bit at right
	for (int k = 7; k >= 0; --k) {
		printf("%u", (bool) (*b & (1 << k)));
	}
}

uint16_t valSum(const uint8_t *packet, size_t len) {
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

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool forward(uint8_t *packet, size_t len) {
  uint16_t exp_sum = (packet[10] << 8) + packet[11];
  packet[10] = 0;
  packet[11] = 0;
  // get IP header length
  size_t h_len = (packet[0] & 0x0F) * 4;  // in byte
  // 1. check valsum
  // if (valSum(packet, h_len) != exp_sum) return false;
  // 2. ttl -= 1
  packet[8] -= 1;
  // 3. update valsum
  uint16_t val_sum = valSum(packet, h_len);
  // reinterpret_cast<uint16_t&>(packet[10]) = val_sum;
  packet[10] = val_sum >> 8;
  packet[11] = val_sum;

  return true;
}
