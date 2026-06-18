#include "display.hpp"
#include "dissector.h"
#include <cstdio>
#include <netinet/in.h>

//ANSI colours
#define COL_RESET  "\033[0m"
#define COL_TCP    "\033[36m"   // cyan
#define COL_UDP    "\033[33m"   // yellow
#define COL_ICMP   "\033[35m"   // magenta
#define COL_ARP    "\033[32m"   // green
#define COL_OTHER  "\033[37m"   // white

static const char* proto_color(uint8_t proto) {
    switch (proto) {
        case IPPROTO_TCP:  return COL_TCP;
        case IPPROTO_UDP:  return COL_UDP;
        case IPPROTO_ICMP: return COL_ICMP;
        case 0:            return COL_ARP;
        default:           return COL_OTHER;
    }
}

static const char* proto_name(uint8_t proto) {
    switch (proto) {
        case IPPROTO_TCP:  return "TCP";
        case IPPROTO_UDP:  return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        case 0:            return "ARP";
        default:           return "???";
    }
}

void Display::print_banner() {
    printf("\n  rawsight v0.1 - raw packet dissector\n\n");
}

void Display::print_packet(const Packet& p) {
    const char* col = proto_color(p.protocol);

    if (p.protocol == IPPROTO_TCP || p.protocol == IPPROTO_UDP) {
        printf("%s[%s]%s %s:%u -> %s:%u  (%zu bytes)\n",
               col, proto_name(p.protocol), COL_RESET,
               p.src_ip.c_str(), p.src_port,
               p.dst_ip.c_str(), p.dst_port,
               p.length);
    } else if (p.protocol == 0) {
        //ARP — no ports, no IPs
        printf("%s[ARP]%s %s -> %s\n",
               col, COL_RESET,
               p.src_mac.c_str(), p.dst_mac.c_str());
    } else {
        printf("%s[%s]%s %s -> %s  (%zu bytes)\n",
               col, proto_name(p.protocol), COL_RESET,
               p.src_ip.c_str(), p.dst_ip.c_str(),
               p.length);
    }
    if(!p.info.empty())
        printf("%s\n",p.info.cstr());
}