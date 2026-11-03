#include "icmp.h"
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <string.h>

void dissect_icmp(const uint8_t* payload, size_t len, char* info, size_t info_len) {
    if (len < sizeof(struct icmphdr)) {
        snprintf(info, info_len, "  [ICMP] truncated\n");
        return;
    }

    // struct icmphdr isn't packed and needs 4-byte alignment, but after the
    // 14-byte ethernet header the payload usually isn't aligned - copy it out
    struct icmphdr icmp;
    memcpy(&icmp, payload, sizeof(icmp));
    const struct icmphdr* hdr = &icmp;

    
    const char* type_str = "unknown";
    switch (hdr->type) {
        case ICMP_ECHO:      type_str = "Echo Request"; break;
        case ICMP_ECHOREPLY: type_str = "Echo Reply";   break;
        case ICMP_DEST_UNREACH: type_str = "Dest Unreachable"; break;
        case ICMP_TIME_EXCEEDED: type_str = "Time Exceeded";   break;
    }

    snprintf(info, info_len, "  [ICMP] type=%u (%s) code=%u\n",
           hdr->type, type_str, hdr->code);
}