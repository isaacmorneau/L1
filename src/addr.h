#pragma once

#include <stdint.h>

int resolve_ip(char* host, uint32_t* addr);
int resolve_gateway(uint32_t* addr);
int resolve_local_ip(const char* iface, uint32_t* addr);
int resolve_local_mac(const char* iface, uint8_t mac[6], int* ifindex);
int resolve_remote_mac(uint32_t ip, uint8_t mac[6]);

int read_mac_str(const char* macstr, uint8_t mac[6]);

void print_ip(uint32_t addr);
void print_mac(uint8_t mac[6]);
