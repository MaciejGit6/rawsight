#pragma once
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <netinet/in.h> 
//netinet -> INET_ADDRSTRLEN

const uint8_t* parse_ipv4(const uint8_t* buf, size_t len,
                           char* src_ip, char* dst_ip,
                           uint8_t* protocol);

typedef struct {
    uint8_t ihl_version;
    uint8_t tos;

    uint16_t total_length;
    uint16_t id;
    uint16_t flags_offset;

    uint8_t ttl;
    uint8_t protocol;

    uint16_t checksum;
    
    uint32_t src;
    uint32_t dst;
}__attribute__((packed)) ipv4_header_t;

#define IPV4_IHL_BYTES(hdr) (((hdr)->ihl_version & 0x0F)*4)