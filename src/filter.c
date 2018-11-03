#define _DEFAULT_SOURCE

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

    set_filter(t.sock);

    while ((nread = read(t.sock, buffer, 4096)) != -1) {
        if ((unsigned long)nread < (sizeof(struct ether_header) + sizeof(struct iphdr)
                                       + sizeof(struct udphdr) + sizeof(struct dnshdr))) {
            //must be malformed, its smaller than the header
            continue;
        }
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

        char* name = (char*)(dhdr + 1);
        while (name < buffer + nread) {
            printf("name: %hhu\n", name[0]);
            for (uint8_t i = 0; i < name[0]; ++i) {
                printf("%02hhX", name[i + 1]);
            }
            name += name[0] + 1;
            puts("");
        }
    }
    perror("read");
    return NULL;
}
