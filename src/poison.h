#pragma once

#include <stdint.h>

typedef struct {
    int sock;
    int ifindex;
    uint32_t cip;
    uint32_t gip;
    uint32_t dip;
    uint8_t omac[6];
    uint8_t cmac[6];
    uint8_t gmac[6];
} targets_t;

int peep_sock(const char * iface);

void* zerg_arp(void* targets);
