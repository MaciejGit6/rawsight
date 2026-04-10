#ifndef UDP_H
#define UDP_H
#include <stdint.h>

typedef struct{
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;

}--attribute--((packed)) udp_header_t;

#endif