#pragma once

#include <stdint.h>

int resolve_ip(char* host, uint32_t* addr);
int resolve_gateway(uint32_t* addr);
int resolve_local_ip(uint8_t mac[6], uint32_t* addr);
int resolve_local_mac(uint8_t mac[6]);
int resolve_remote_mac(uint32_t ip, uint8_t mac[6]);

void print_ip(uint32_t addr);
void print_mac(uint8_t mac[6]);
