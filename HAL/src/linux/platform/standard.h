#include "router_hal.h"

// configure this to match the output of `ip a`
const char *interfaces[N_IFACE_ON_BOARD] = {
    "eth1",
    "eth2",
    // "en3",
    // "en4",
};
