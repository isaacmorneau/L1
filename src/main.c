#include <getopt.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "addr.h"

static void print_help() {
    puts("==>target<==\n"
         "\t[s]rcip  - the IP of the target to poison\n"
         "\t[m]ac    - the MAC address of the target\n"
         "specifying MAC will disable the discovery from the network\n"
         "one or the other is needed but not both\n"
         "\n==>injection<==\n"
         "\t[d]stip  - the IP of the crafted dns query, will default to local IP\n"
         "\th[o]stip - the host of the crafted dns query, will be looked up and used in place of a "
         "raw ip\n"
         "one or the other is needed but not both\n"
         "\n==>misc<==\n"
         "\t[h]elp   - this message");
}

int main(int argc, char **argv) {
    int choice;
    int option_index = 0;

    char *srcip = NULL;
    char *dstip = NULL;
    char *host  = NULL;
    char *mac   = NULL;

    if (argc == 1) {
        print_help();
        return EXIT_SUCCESS;
    }

    while (1) {
        static struct option long_options[] = {{"srcip", required_argument, 0, 's'},
            {"dstip", required_argument, 0, 'd'}, {"hostip", required_argument, 0, 'o'},
            {"mac", required_argument, 0, 'm'}, {"help", no_argument, 0, 'h'}, {0, 0, 0, 0}};

        choice = getopt_long(argc, argv, "sdmh", long_options, &option_index);

        if (choice == -1)
            break;

        switch (choice) {
            case 'h':
                print_help();
                return EXIT_SUCCESS;
            case 's':
                srcip = optarg;
                break;
            case 'd':
                dstip = optarg;
                break;
            case 'o':
                host = optarg;
                break;
            case 'm':
                mac = optarg;
                break;
            default:
                print_help();
                return EXIT_FAILURE;
        }
    }

    if (srcip && mac) {
        fputs("cannot specify both MAC and IP of target\n", stderr);
        return EXIT_FAILURE;
    }

    if (host && dstip) {
        fputs("cannot specify both host and IP of target\n", stderr);
        return EXIT_FAILURE;
    }

    uint32_t ip;
    uint8_t mac[6];

    if (resolve_ip(host, srcip, &ip)) {
        fputs("unable to resolve IP\n", stderr);
        return EXIT_FAILURE;
    }

    if (resolve_local_mac(mac)) {
        fputs("unable to resolve MAC\n", stderr);
        return EXIT_FAILURE;
    }

    print_ip(ip);

    print_mac(mac);

    return EXIT_SUCCESS;
}
