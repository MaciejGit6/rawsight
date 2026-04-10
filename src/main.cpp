#include "capture.h"
#include "pcap_reader.h"
#include "packet.hpp"
#include "filter.hpp"
#include "display.hpp"

#include <iostream>
#include <cstring>

static Filter g_filter;


extern "C" void packet_receiver(const uint8_t* buf, ssize_t len) {
    printf("[*] captured packet, %zd bytes\n", len);
    (void)buf;
}



int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "usage: sudo ./rawsight <interface>\n";
        std::cerr << "       ./rawsight --file <capture.pcap>\n";
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