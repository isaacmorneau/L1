#pragma once

#include <stdint.h>

struct __attribute__((packed)) arp_header
{
        uint16_t arp_hd;
        uint16_t arp_pr;
        uint8_t arp_hdl;
        uint8_t arp_prl;
        uint16_t arp_op;
        uint8_t arp_sha[6];
        uint8_t arp_spa[4];
        uint8_t arp_dha[6];
        uint8_t arp_dpa[4];
};

void forge_arp_reply(uint8_t *buffer, uint32_t ip, uint8_t mac[6]);

