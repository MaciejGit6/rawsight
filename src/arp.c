#include "arp.h"
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <stdio.h>


typedef struct {
    uint16_t htype; 
    uint16_t ptype; 
    uint8_t  hlen;  
    uint8_t  plen;  
    uint16_t oper;  
    uint8_t  sha[6]; 
    uint8_t  spa[4]; 
    uint8_t  tha[6]; 
    uint8_t  tpa[4]; 
} __attribute__((packed)) ArpPacket;

void dissect_arp(const uint8_t* payload, size_t len) {
    if (len < sizeof(ArpPacket)) {
        printf("  [ARP] truncated\n");
        return;
    }

    const ArpPacket* arp = (const ArpPacket*)payload;
    uint16_t op = ntohs(arp->oper);

    char spa[INET_ADDRSTRLEN], tpa[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, arp->spa, spa, sizeof(spa));
    inet_ntop(AF_INET, arp->tpa, tpa, sizeof(tpa));

    if (op == ARPOP_REQUEST) {
        printf("  [ARP] Who has %s? Tell %s\n", tpa, spa);
    } else if (op == ARPOP_REPLY) {
        printf("  [ARP] %s is at %02x:%02x:%02x:%02x:%02x:%02x\n",
               spa,
               arp->sha[0], arp->sha[1], arp->sha[2],
               arp->sha[3], arp->sha[4], arp->sha[5]);
    } else {
        printf("  [ARP] op=%u %s -> %s\n", op, spa, tpa);
    }
}