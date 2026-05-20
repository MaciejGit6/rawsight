#include "tcp.h"
#include <arpa/inet.h>
#include <stddef.h>
#include <sys/types.h>

const uint8_t* parse_tcp(const uint8_t* buf, size_t len,
                          uint16_t* src_port, uint16_t* dst_port) {
    if (len < sizeof(tcp_header_t)) return NULL;

    const tcp_header_t* hdr = (const tcp_header_t*)buf;
    *src_port = ntohs(hdr->src_port);
    *dst_port = ntohs(hdr->dst_port);

    size_t hlen = TCP_HDR_LEN(hdr);
    if (hlen < 20 || hlen > len) return NULL;

    return buf + hlen;
}