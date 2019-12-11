#include "router_hal.h"

// to use this, please define HAL_PLATFORM_TESTING
// configure this to match the output of `ip a`
const char *interfaces[N_IFACE_ON_BOARD] = {
    "veth-r21",
    "veth-r22",
    "enp0s31f6",
    "eth3",
};