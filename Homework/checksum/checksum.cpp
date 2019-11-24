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

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
  // 1. zerolize cheksum area
  uint16_t expected = (packet[10] << 8) + packet[11];
  packet[10] = 0;
  packet[11] = 0;
  // get IP header length
  size_t h_len = (packet[0] & 0b00001111) * 4;  // in byte
  // 2. suming up all 16-bit
  uint32_t sum = 0;
  uint32_t overflow = 0;
  for (size_t i = 0; i < h_len; i += 2) { // step 2 uint_8s
    sum += (packet[i] << 8) + packet[i+1];
    do {
      overflow = (sum & 0xFFFF0000) >> 16; // take hi 16 bits of sum
      sum &= 0x0000FFFF;  // trunc to lo 16 bits
      sum += overflow;
    } while (overflow != 0);
  }
  sum = ~sum & 0x0000FFFF; // logical not

  return sum == expected;
}
