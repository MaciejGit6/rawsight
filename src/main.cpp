#include "captur.h"
#include "packet.hpp"
#include "filter.hpp"
#include "display.hpp"
#include <iostream>

static Filter g_filter;

extern "C" void packet_receiver(
    const char* src_mac, 
    const char* dst_mac, 
    const char* src_ip,
    const char* dst_ip,

    uint8_t protocol,
    uint16_t src_port, 
    uint16_t dst_port,
    size_t length)
{
    Packet p;
    p.src_mac = src_mac;
    p.dst_mac = dst_mac;
    p.src_ip = src_ip ? src_ip : "";
    p.dst_ip = dst_ip ? dst_ip : "";
    p.protocol = protocol;
    p.src_port = src_port;
    p.dst_port = dst_port;
    p.length = length;

    if(g_filter.matched(p)){
        Display::print_packet(p);    
    }
}

int main(int argc, char* argv[]){
    if(argc < 2){

        std::cerr << "Usage: sudo ./rawsight <interface> [--tcp|--udp]\n";
        return 1;
    }

    if(argc == 3){
        std::string flag = argv[2];
        if(flag == "--tcp") g_filter.enable_tcp();
        if(flag == "--udp")g_filter.enable_udp();
    }

    Display::print_banner();

    int sock = open_raw_socket(argv[1]);
    if(sock < 0) return 1;

    capture_loop(sock, packet_receiver);
    return 0;
}