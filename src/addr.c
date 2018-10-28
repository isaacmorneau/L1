#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stropts.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "addr.h"

int resolve_ip(char* host, char* ip, uint32_t* addr) {
    if (host) {
        struct addrinfo hints;
        struct addrinfo* rp;

        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_flags    = AI_PASSIVE; // All interfaces

        //null the service as it only accepts strings and we have the port already
        if (getaddrinfo(host, NULL, &hints, &rp) != 0) {
            perror("getaddrinfo");
            return -1;
        }

        //assuming the first result returned will be correct
        if (!rp) {
            fputs("unabled to find host address\n", stderr);
            return -1;
        }

        if (rp->ai_family != AF_INET) {
            //only can do ipv4 right now
            return -1;
        }
        *addr = ((struct sockaddr_in*)rp->ai_addr)->sin_addr.s_addr;
        freeaddrinfo(rp);
    } else if (ip) {
        struct in_addr inaddr;
        if (!inet_aton(ip, &inaddr)) {
            return -1;
        }
        *addr = inaddr.s_addr;
    } else {
        return -1;
    }
    return 0;
}

int resolve_local_mac(uint8_t mac[6]) {
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) {
        perror("socket");
        return -1;
    };

    struct ifconf ifc;
    char buf[1024];
    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {
        perror("ioctl");
        return -1;
    }

    struct ifreq* it = ifc.ifc_req;

    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (struct ifreq ifr; it != end; ++it) {
        strncpy(ifr.ifr_name, it->ifr_name, sizeof(it->ifr_name));
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (!(ifr.ifr_flags & IFF_LOOPBACK)) {
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
                    return 0;
                }
            }
        } else {
            perror("ioctl");
            return -1;
        }
    }

    return -1;
}

void print_ip(uint32_t addr) {
    printf("IP: %u.%u.%u.%u\n", *((uint8_t*)&addr), *((uint8_t*)&addr + 1), *((uint8_t*)&addr + 2),
        *((uint8_t*)&addr + 3));
}
void print_mac(uint8_t mac[6]) {
    printf("MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
