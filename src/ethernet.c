#include "ethernet.h"
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

void mac_to_str(const uint8_t* mac, char* out, size_t out_len){
    snprintf(out, out_len, "%02x:%02x:%02x:%02x:%02x:%02x",
    mac[0], mac[1], mac[2], mac[4], mac[5]);
}

const uint8_t* parse_ethernet(const uint8_t* buf, ssize_t len, char* src_mac, char* dst_mac, uint16_t* ethertype){
    if(len < ETH_HLEN){
        return NULL;
    }
    const eth_header_t* eth = (const eth_header_t*)buf;

    mac_to_str(eth->src, src_mac, 18);
    mac_to_str(eth->dst, dst_mac, 18);
    *ethertype = ntohs(eth->etherntype);

    return buf + ETH_HLEN;
    
}



