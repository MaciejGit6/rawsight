#ifndef TCP_H
#define TCP_H
#include <stdint.h>

typedef struct{
    uint16_t src_port;
    uint16_t


    uint32_t
    uint32_t 

    uint8_t data_offset;
    uint8_t flags;
    
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;


}__attribute__((packed))tcp_header_t;

#define TCP_HDR_LEN(hdr) (((hdr)->data_offset >> 4)*4)
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_RST 0x04