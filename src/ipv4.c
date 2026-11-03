#include "ipv4.h"
#include <arpa/inet.h>
#include <string.h>
#include <sys/types.h>

const uint8_t* parse_ipv4(const uint8_t* buf, size_t len,
                           char* src_ip, char* dst_ip,
                           uint8_t* protocol, size_t* l4_len) {
    if (len < 20) return NULL;

    const ipv4_header_t* hdr = (const ipv4_header_t*)buf;
    size_t ihl = IPV4_IHL_BYTES(hdr);
    if (ihl < 20 || ihl > len) return NULL;

    // total_length bounds the datagram, anything after it is ethernet padding
    size_t total = ntohs(hdr->total_length);
    if (total < ihl) return NULL;
    if (total > len) total = len;   // truncated capture

    inet_ntop(AF_INET, &hdr->src, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &hdr->dst, dst_ip, INET_ADDRSTRLEN);
    *protocol = hdr->protocol;

    *l4_len = total - ihl;
    return buf + ihl;
}

// non-first fragments have no L4 header, so their data must not be parsed as one
int ipv4_is_later_fragment(const uint8_t* buf) {
    const ipv4_header_t* hdr = (const ipv4_header_t*)buf;
    return (ntohs(hdr->flags_offset) & IPV4_FRAG_OFFSET_MASK) != 0;
}
