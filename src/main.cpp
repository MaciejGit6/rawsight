#include "capture.h"
#include "pcap_reader.h"
#include "dissector.h"
#include "packet.hpp"
#include "filter.hpp"
#include "display.hpp"

#include <iostream>
#include <cstring>
#include <getopt.h>
#include "config.h"

static Filter  g_filter;
static int     g_count     = 0;
static int     g_max       = 0;   // 0 = unlimited

static void print_usage(const char* prog) {
    fprintf(stderr,
        "Usage: %s -i <iface> [-n <count>] [-p tcp|udp|icmp] [-f <ip>]\n"
        "       %s -r <file.pcap>\n"
        "  -i  live interface (e.g. eth0)\n"
        "  -r  read from pcap file instead of live capture\n"
        "  -n  stop after N packets\n"
        "  -p  protocol filter: tcp, udp, icmp\n"
        "  -f  filter by IP address\n",
        prog, prog);
}

extern "C" void packet_receiver(const uint8_t* buf, ssize_t len) {
    DissectedPacket dp;
    if (!dissect_packet(buf, len, &dp)) return;

    Packet p;
    p.src_mac  = dp.src_mac;
    p.dst_mac  = dp.dst_mac;
    p.src_ip   = dp.src_ip;
    p.dst_ip   = dp.dst_ip;
    p.protocol = dp.protocol;
    p.src_port = dp.src_port;
    p.dst_port = dp.dst_port;
    p.length   = dp.length;

    if (!g_filter.matches(p)) return;

    Display::print_packet(p);
    ++g_count;

    if (g_max > 0 && g_count >= g_max) {
        // raise SIGINT to trigger graceful shutdown
        raise(SIGINT);
    }
}

int main(int argc, char* argv[]) {
    const char* iface      = nullptr;
    const char* pcap_file  = nullptr;
    const char* proto      = nullptr;
    int         max_pkts   = 0;

    int opt;
    while ((opt = getopt(argc, argv, "i:r:n:p:f:")) != -1) {
        switch (opt) {
            case 'i': iface     = optarg;        break;
            case 'r': pcap_file = optarg;        break;
            case 'n': max_pkts  = atoi(optarg);  break;
            case 'p': proto     = optarg;        break;
            case 'f': g_filter.set_ip(optarg);   break;
            default:  print_usage(argv[0]); return 1;
        }
    }

    if (proto) {
        if (strcmp(proto, "tcp")  == 0) g_filter.enable_tcp_only();
        else if (strcmp(proto, "udp") == 0) g_filter.enable_udp_only();
        // icmp handled at dissector level
    }

    g_max = max_pkts;
    Display::print_banner();

    if (pcap_file) {
        return read_pcap_file(pcap_file, packet_receiver);
    }

    if (!iface) {
        fprintf(stderr, "[-] Provide -i <iface> or -r <file.pcap>\n");
        print_usage(argv[0]);
        return 1;
    }

    int sock = open_raw_socket(iface);
    if (sock < 0) return 1;

    if (proto) attach_bpf_filter(sock, proto);

    capture_loop(sock, packet_receiver);
    return 0;
}