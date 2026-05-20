#include "ipv4.h"
#include <arpa/inet.h>
#include <string.h>
#include <sys/types.h>

const uint8_t* parse_ipv4(const uint8_t* buf, size_t len,
                           char* src_ip, char* dst_ip,
                           uint8_t* protocol) {
    if (len < 20) return NULL;

    const ipv4_header_t* hdr = (const ipv4_header_t*)buf;
    size_t ihl = IPV4_IHL_BYTES(hdr);
    if (ihl < 20 || ihl > len) return NULL;

    inet_ntop(AF_INET, &hdr->src, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &hdr->dst, dst_ip, INET_ADDRSTRLEN);
    *protocol = hdr->protocol;

    return buf + ihl;
}