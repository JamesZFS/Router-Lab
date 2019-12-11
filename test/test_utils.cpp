#include <cstdio>
#include <cstring>
#include <stdint.h>

uint32_t endianSwap(uint32_t a) {
  return (a >> 24) | ((a & 0x00FF0000) >> 8) | ((a & 0x0000FF00) << 8) | ((a & 0x000000FF) << 24);
}

static uint32_t countTrailingOne(uint32_t a) {
    uint32_t len;
    for (len = 0; len < 32; ++len) {
        if ((a & 0x01) == 0) {
            break;
        }
        a >>= 1;
    }
    return len;
}

int main() {
  uint32_t a = 0xf10203f4;
  uint32_t b = endianSwap(a);
  printf("0x%.8x\n", b);

  a = 0x03ffffff;
  printf("mask to len: %u\n", countTrailingOne(a));
}
