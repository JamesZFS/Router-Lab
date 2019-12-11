#include "router_hal.h"

// configure this to match the output of `ip a`
const char *interfaces[N_IFACE_ON_BOARD] = {
    "veth-r21",
    "veth-r22",
    // "en3",
    // "en4",
};
