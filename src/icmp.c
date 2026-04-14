#include "icmp.h"
#include <netinet/ip_icmp.h>
#include <stdio.h>

void dissect_icmp(const uint8_t* payload, size_t len) {
    if (len < sizeof(struct icmphdr)) {
        printf("  [ICMP] truncated\n");
        return;
    }

    const struct icmphdr* hdr = (const struct icmphdr*)payload;

    
    const char* type_str = "unknown";
    switch (hdr->type) {
        case ICMP_ECHO:      type_str = "Echo Request"; break;
        case ICMP_ECHOREPLY: type_str = "Echo Reply";   break;
        case ICMP_DEST_UNREACH: type_str = "Dest Unreachable"; break;
        case ICMP_TIME_EXCEEDED: type_str = "Time Exceeded";   break;
    }

    printf("  [ICMP] type=%u (%s) code=%u\n",
           hdr->type, type_str, hdr->code);
}