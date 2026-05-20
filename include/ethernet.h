#pragma once 
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>


#define ETHERNETYPE_IPV4 0x0800
#define ETHERNETYPE_IPV6 0x86DD
#define ETHERNETYPE_ARP 0x0806


#define ETH_ALEN 6
#define ETH_HLEN 14

void mac_to_str (const uint8_t* mac, char* out, size_t out_len);
const uint8_t* parse_ethernet(const uint8_t* buf, ssize_t len, char* src_mac,
    char* dst_mac,  uint16_t* ethertype);


typedef struct{
    
    uint8_t dst[ETH_ALEN];
    uint8_t src[ETH_ALEN];
    uint16_t ethertype;

}__attribute((packed)) eth_header_t;
