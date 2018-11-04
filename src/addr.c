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


/*
 * function:
 *    read_mac_str
 *
 * return:
 *    int success or failure
 *
 * parameters:
 *    const char* macstr the string of a mac
 *    uint8_t mac[6] the mac raw data
 *
 * notes:
 *      reads a formatted mac string into a raw buffer
 *
 * */

int read_mac_str(const char* macstr, uint8_t mac[6]) {
    return (sscanf(macstr, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", mac, mac + 1, mac + 2,
                mac + 3, mac + 4, mac + 5)
        != 6);
}


/*
 * function:
 *    print_ip
 *
 * return:
 *    void
 *
 * parameters:
 *    uint32_t addr the ip to print
 *
 * notes:
 *      prints the raw ip as a string
 *
 * */

void print_ip(uint32_t addr) {
    printf("IP: %u.%u.%u.%u\n", *((uint8_t*)&addr), *((uint8_t*)&addr + 1), *((uint8_t*)&addr + 2),
        *((uint8_t*)&addr + 3));
}


/*
 * function:
 *    print_mac
 *
 * return:
 *    void
 *
 * parameters:
 *    uint8_t mac[6] the mac to print
 *
 * notes:
 *      prints the specified mac
 *
 * */

void print_mac(uint8_t mac[6]) {
    printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}


/*
 * function:
 *    resolve_ip
 *
 * return:
 *    int success or failure
 *
 * parameters:
 *    char* host the string of the host
 *    uint32_t* addr the address to store it in
 *
 * notes:
 *      resolves a host to an ip
 *
 * */

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


/*
 * function:
 *    resolve_local_mac
 *
 * return:
 *    int success or failure
 *
 * parameters:
 *    const char* iface the interface to use
 *    uint8_t mac[6] the mac address to save to
 *    int* ifindex the number of the interface
 *
 * notes:
 *      resolves a mac and interface id from an interface name
 *
 * */

int resolve_local_mac(const char* iface, uint8_t mac[6], int* ifindex) {
    int fd;
    struct ifreq ifr;
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1) {
        return -1;
    }

    if ((ioctl(fd, SIOCGIFHWADDR, &ifr)) == -1) {
        close(fd);
        return -1;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
        close(fd);
        return -1;
    }

    *ifindex = ifr.ifr_ifindex;

    close(fd);
    return 0;
}


/*
 * function:
 *    resolve_remote_mac
 *
 * return:
 *    int success or failure
 *
 * parameters:
 *    uint32_t addr the ip to search
 *    uint8_t mac[6] the mac to find
 *
 * notes:
 *      resolves the mac using a ping and checking the arp response
 *
 * */

int resolve_remote_mac(uint32_t addr, uint8_t mac[6]) {
    char buffer[90];
    snprintf(buffer, 90,
        "export H=\"%u.%u.%u.%u\";ping -nc1 $H 2>&1 >/dev/null;arp -an|grep \"($H)\"|awk '{print "
        "$4}'",
        *((uint8_t*)&addr), *((uint8_t*)&addr + 1), *((uint8_t*)&addr + 2), *((uint8_t*)&addr + 3));
    FILE* macfile;
    if (!(macfile = popen(buffer, "r"))) {
        perror("popen");
        return -1;
    }
    fgets(buffer, 18, macfile);
    pclose(macfile);
    return read_mac_str(buffer, mac);
}


/*
 * function:
 *    resolve_gateway
 *
 * return:
 *    int success or failure
 *
 * parameters:
 *    uint32_t* addr the address to find
 *
 * notes:
 *      gets the gateway ip
 *
 * */

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


/*
 * function:
 *    resolve_local_ip
 *
 * return:
 *    int success or failure
 *
 * parameters:
 *    const char* iface the interface to check
 *    uint32_t* addr the address to find
 *
 * notes:
 *      gets a local ip from an interface
 *
 * */

int resolve_local_ip(const char* iface, uint32_t* addr) {
    int fd;
    struct ifreq ifr;

    if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1) {
        perror("socket");
        return -1;
    }

    ifr.ifr_addr.sa_family = AF_INET;

    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        perror("ioctl");
        close(fd);
        return -1;
    }

    close(fd);

    *addr = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;

    return 0;
}
