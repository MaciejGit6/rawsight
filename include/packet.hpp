#pragma once
#include <cstdint>
#include <string>

struct Packet {
    std::string src_mac;
    std::string dst_mac;
    std::string src_ip;
    std::string dst_ip;
    uint8_t     protocol  = 0;
    uint16_t    src_port  = 0;
    uint16_t    dst_port  = 0;
    size_t      length    = 0;
};