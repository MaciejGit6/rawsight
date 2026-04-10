#pragma once
#include <cstdint>
#include <string>
#include <vector>

struct Packet{

    std::string src_mac;
    std::string dst_mac;
    std::string src_ip;
    std::string dst_ip;


    uint8_t protocol;
    uint16_t src_port;
    uint16_t dst_port;

    size_t length;
}