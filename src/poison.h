#pragma once

#include <stdint.h>

typedef struct {
    int sock;
    uint32_t cip;
    uint32_t gip;
    uint8_t omac[6];
    uint8_t cmac[6];
    uint8_t gmac[6];
} targets_t;

#define IF_INDEX (2)

void* zerg_arp(void* targets);
