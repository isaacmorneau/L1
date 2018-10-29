#include "poison.h"
#include <


void forge_arp_reply(uint8_t *buffer, uint32_t ip, uint8_t mac[6]) {
    socket_address.sll_family   = PF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ARP);
    socket_address.sll_ifindex  = ifindex;
    socket_address.sll_hatype   = ARPHRD_ETHER;
    socket_address.sll_pkttype  = 0; //PACKET_OTHERHOST;
    socket_address.sll_halen    = 0;
    socket_address.sll_addr[6]  = 0x00;
    socket_address.sll_addr[7]  = 0x00;
}
