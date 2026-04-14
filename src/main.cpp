#include "capture.h"
#include "pcap_reader.h"
#include "packet.hpp"
#include "filter.hpp"
#include "display.hpp"

#include <iostream>
#include <cstring>
#include <getopt.h>
#include "config.h"

static void print_usage(const char* prog) {
    fprintf(stderr, "Usage: %s -i <iface> [-n <count>] [-p <proto>]\n", prog);
    fprintf(stderr, "  -i  network interface (e.g. eth0, lo)\n");
    fprintf(stderr, "  -n  stop after N packets (default: unlimited)\n");
    fprintf(stderr, "  -p  protocol filter: tcp, udp, icmp, arp (default: all)\n");
}

static Filter g_filter;


extern "C" void packet_receiver(const uint8_t* buf, ssize_t len) {
    printf("[*] captured packet, %zd bytes\n", len);
    (void)buf;
}



int main(int argc, char* argv[]) {
    CaptureConfig cfg = { nullptr, 0, nullptr };

    int opt;
    while ((opt = getopt(argc, argv, "i:n:p:")) != -1) {
        switch (opt) {
            case 'i': cfg.iface        = optarg;       break;
            case 'n': cfg.max_packets  = atoi(optarg); break;
            case 'p': cfg.proto_filter = optarg;       break;
            default:  print_usage(argv[0]); return 1;
        }
    }

    if (!cfg.iface) {
        fprintf(stderr, "[-] Interface is required.\n");
        print_usage(argv[0]);
        return 1;
    }

    Display::print_banner();

    if (std::string(argv[1]) == "--file") {
        if (argc < 3) {
            std::cerr << "[-] no file specified\n";
            return 1;
        }
        return read_pcap_file(argv[2], packet_receiver);
    }


    int sock = open_raw_socket(argv[1]);
    if (sock < 0) return 1;

    capture_loop(sock, packet_receiver);

    return 0;
}