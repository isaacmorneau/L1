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
#include <unistd.h>

#include "addr.h"
#include "poison.h"

int resolve_ip(char* host, uint32_t* addr) {
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
        fputs("IPv6 not supported\n", stderr);
        //only can do ipv4 right now
        freeaddrinfo(rp);
        return -1;
    }

    *addr = ((struct sockaddr_in*)rp->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(rp);
    return 0;
}

int resolve_local_mac(const char* iface, uint8_t mac[6]) {
    int fd;
    struct ifreq ifr;
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1) {
        return -1;
    }

    if ((ioctl(fd, SIOCGIFHWADDR, &ifr)) == -1) {
        return -1;
    }

    close(fd);

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}

void print_ip(uint32_t addr) {
    printf("IP: %u.%u.%u.%u\n", *((uint8_t*)&addr), *((uint8_t*)&addr + 1), *((uint8_t*)&addr + 2),
        *((uint8_t*)&addr + 3));
}

void print_mac(uint8_t mac[6]) {
    printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int resolve_remote_mac(uint32_t addr, uint8_t mac[6]) {
    char buffer[90];
    snprintf(buffer, 90,
        "export H=\"%u.%u.%u.%u\";ping -nc1 $H 2>&1 >/dev/null;arp -an|grep $H|awk '{print $4}'",
        *((uint8_t*)&addr), *((uint8_t*)&addr + 1), *((uint8_t*)&addr + 2), *((uint8_t*)&addr + 3));
    FILE* macfile;
    if (!(macfile = popen(buffer, "r"))) {
        perror("popen");
        return -1;
    }
    fgets(buffer, 18, macfile);
    pclose(macfile);
    if (sscanf(buffer, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", mac, mac + 1, mac + 2, mac + 3,
            mac + 4, mac + 5)
        == 6) {
        return 0;
    }
    return 1;
}

int resolve_gateway(uint32_t* addr) {
    FILE* ipfile;
    uint8_t ip[4];
    int ret;
    if (!(ipfile = popen("ip route|grep default|awk '{print $3}'", "r"))) {
        perror("popen");
        return -1;
    }
    ret = fscanf(ipfile, "%hhu.%hhu.%hhu.%hhu", ip, ip + 1, ip + 2, ip + 3);
    pclose(ipfile);

    *addr = *ip | ip[1] << 8 | ip[2] << 16 | ip[3] << 24;

    return ret == 4 ? 0 : -1;
}

int resolve_local_ip(uint8_t mac[6], uint32_t* addr) {
    char buffer[104];
    uint8_t ip[4];
    FILE* ipfile;
    int ret;

    snprintf(buffer, 104,
        "ip addr|grep -iA1 \"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\"|tail -1|awk '{print "
        "$2}'|grep -Eo '^[^/]*'",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    if (!(ipfile = popen(buffer, "r"))) {
        perror("popen");
        return -1;
    }
    ret = fscanf(ipfile, "%hhu.%hhu.%hhu.%hhu", ip, ip + 1, ip + 2, ip + 3);

    pclose(ipfile);

    *addr = *ip | ip[1] << 8 | ip[2] << 16 | ip[3] << 24;

    return ret == 4 ? 0 : -1;
}
