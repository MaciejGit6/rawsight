#pragma once 
#include <stdin.h.

#define ETHERNETYPE_IPV4 0x0800
#define ETHERNETYPE_IPV6 0x86DD
#define ETHERNETYPE_ARP 0x0806


#define ETH_ALEN 6
#define ETH_HLEN 14


typedef struct{
    
    uint8_t dst[ETH_ALEN];
    uint8_t src[ETH_ALEN];
    uint16_t ethertype;

}__attribute((packed)) eth_header_t;
