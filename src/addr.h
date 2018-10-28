#pragma once

#include <stdint.h>

int resolve_ip(char* host, char* ip, uint32_t* addr);
int resolve_local_mac(uint8_t mac[6]);

void print_ip(uint32_t addr);
void print_mac(uint8_t mac[6]);
