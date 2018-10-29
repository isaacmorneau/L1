#include <getopt.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "addr.h"

static void print_help() {
    puts("==>target<==\n"
         "\t[p]snip - the host of the target to poison\n"
         "\t[g]ateip - the IP of the gateway, will default to local routing lookup\n"
         "\n==>injection<==\n"
         "\t[d]stip - the host of the crafted dns query, will default to local IP\n"
         "one or the other is needed but not both\n"
         "\n==>misc<==\n"
         "\t[h]elp - this message");
}

int main(int argc, char **argv) {
    int choice;
    int option_index = 0;

    char *dstip  = NULL;
    char *gateip = NULL;
    char *host   = NULL;
    char *psnip  = NULL;

    if (argc == 1) {
        print_help();
        return EXIT_SUCCESS;
    }

    while (1) {
        static struct option long_options[] = {{"psnip", required_argument, 0, 'p'},
            {"gateip", required_argument, 0, 'g'}, {"dstip", required_argument, 0, 'd'},
            {"hostip", required_argument, 0, 'o'}, {"help", no_argument, 0, 'h'}, {0, 0, 0, 0}};

        choice = getopt_long(argc, argv, "p:d:g:o:h", long_options, &option_index);

        if (choice == -1) {
            break;
        }

        switch (choice) {
            case 'h':
                print_help();
                return EXIT_SUCCESS;
            case 'g':
                gateip = optarg;
                break;
            case 'p':
                psnip = optarg;
                break;
            case 'd':
                dstip = optarg;
                break;
            case 'o':
                host = optarg;
                break;
            default:
                print_help();
                return EXIT_FAILURE;
        }
    }

    if (host && dstip) {
        fputs("cannot specify both host and IP of target\n", stderr);
        return EXIT_FAILURE;
    }

    if (!(psnip && (host || dstip))) {
        print_help();
        return EXIT_FAILURE;
    }

    uint32_t pip, dip, gip;
    uint8_t umac[6], pmac[6], gmac[6];

    if (resolve_ip(psnip, &pip)) {
        fputs("unable to resolve source IP\n", stderr);
        return EXIT_FAILURE;
    }

    if (resolve_ip(dstip ? dstip : host, &dip)) {
        fputs("unable to resolve dest IP\n", stderr);
        return EXIT_FAILURE;
    }

    if (gateip) {
        if (resolve_ip(gateip, &gip)) {
            fputs("unable to resolve gateway IP\n", stderr);
            return EXIT_FAILURE;
        }
    } else {
        if (resolve_gateway(&gip)) {
            fputs("unable to resolve gateway IP\n", stderr);
            return EXIT_FAILURE;
        }
    }

    if (resolve_local_mac(umac)) {
        fputs("unable to resolve local MAC\n", stderr);
        return EXIT_FAILURE;
    }

    if (resolve_remote_mac(pip, pmac)) {
        fputs("unable to resolve remote MAC\n", stderr);
        return EXIT_FAILURE;
    }

    if (resolve_remote_mac(gip, gmac)) {
        fputs("unable to resolve gateway MAC\n", stderr);
        return EXIT_FAILURE;
    }

    puts("==-poison-==");
    print_ip(pip);
    print_mac(pmac);

    puts("==-redirect to-==");
    print_ip(dip);

    puts("==-us-==");
    print_mac(umac);

    puts("==-gateway-==");
    print_ip(gip);
    print_mac(gmac);

    return EXIT_SUCCESS;
}
