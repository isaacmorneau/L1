#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    static uint8_t buffer[USHRT_MAX];
    memset(buffer, '~', USHRT_MAX-1);
    static dns_hdr_t* dnshdr = (dns_hdr_t*)buffer;
    int nread;
    //copy it local
    targets_t t = *(targets_t*)targets;

    set_filter(t.sock);

    while ((nread = read(t.sock, buffer, USHRT_MAX)) != -1) {
        if ((unsigned long)nread < sizeof(dns_hdr_t)) {
            //must be malformed, its smaller than the header
            continue;
        }
        printf("id: %hX\n", dnshdr->id);
        printf("rec: %c\n", dnshdr->rd ? 'y' : 'n');
        printf("truc: %c\n", dnshdr->tc ? 'y' : 'n');
        printf("auth: %c\n", dnshdr->aa ? 'y' : 'n');
        printf("op: %c\n", dnshdr->opcode);
        printf("qr: %c\n", dnshdr->qr ? 'y' : 'n');
        printf("rcode: %c\n", dnshdr->rcode);
        printf("check: %c\n", dnshdr->cd ? 'y' : 'n');
        printf("auth2: %c\n", dnshdr->ad ? 'y' : 'n');
        printf("z?: %c\n", dnshdr->z ? 'y' : 'n');
        printf("reca: %c\n", dnshdr->ra ? 'y' : 'n');
        printf("qcount: %hX\n", dnshdr->q_count);
        printf("ans: %hX\n", dnshdr->ans_count);
        printf("auth: %hX\n", dnshdr->auth_count);
        printf("add: %hX\n", dnshdr->add_count);

        char* name = (char*)buffer + sizeof(dns_hdr_t);
        while (name < buffer + nread) {
            printf("name: %hhu\n", name[0]);
            for (uint8_t i = 0; i < name[0]; ++i) {
                printf("%02hhX", name[i+1]);
            }
            name += name[0];
            puts("");
        }
    }
    perror("read");
    return NULL;
}
