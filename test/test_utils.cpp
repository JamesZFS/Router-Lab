#include <cstdio>
#include <cstring>
#include <stdint.h>

uint32_t endianSwap(uint32_t a) {
  return (a >> 24) | ((a & 0x00FF0000) >> 8) | ((a & 0x0000FF00) << 8) | ((a & 0x000000FF) << 24);
}

int main() {
  uint32_t a = 0xf10203f4;
  uint32_t b = endianSwap(a);
  printf("0x%.8x\n", b);
}
