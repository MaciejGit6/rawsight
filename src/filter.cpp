#include "display.hpp"
#include <iostream>

void Display::print_banner() {
    std::cout << "\n  rawsight v0.1 - raw packet dissector\n\n";
}

void Display::print_packet(const Packet& p) {
    (void)p;
}