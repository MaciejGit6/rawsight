#ifndef UDP_H
#define UDP_H
#include <stdint.h>
#include <stddef.h>

typedef struct{
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;

}__attribute__((packed)) udp_header_t;

void parse_udp(const uint8_t* buf, size_t len, 
    uint16_t* src_port, uint16_t*  dst_port);

#endif