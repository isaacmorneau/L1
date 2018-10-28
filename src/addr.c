#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "addr.h"

int resolve_ip(char* host, char* ip, uint32_t* addr) {
    if (host) {
        //getaddrinfo
    } else if (ip) {
        struct in_addr inaddr;
        if (inet_aton(ip, &inaddr) != 1) {
            *addr = inaddr.s_addr;
            return -1;
        }
    } else {
        return -1;
    }
    return 0;
}
