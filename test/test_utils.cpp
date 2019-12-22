#include <cstdio>
#include <cstring>
#include <stdint.h>
#include <cassert>

uint32_t endianSwap(uint32_t a) {
  return (a >> 24) | ((a & 0x00FF0000) >> 8) | ((a & 0x0000FF00) << 8) | ((a & 0x000000FF) << 24);
}

template<typename T>
static void showBits(T a)
{
	auto b = (T *) (&a);  // low bit at right
	for (int k = 8 * sizeof(T) - 1; k >= 0; --k) {
		printf("%u", (bool) (*b & (1 << k)));
	}
  printf("\n");
}

static bool checkMask(uint32_t mask) {
  return (mask | (mask - 1)) == 0xFFFFFFFF;
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
  showBits((uint8_t)240);
  assert(checkMask(0xFFFFF000));
  return 0;
}
