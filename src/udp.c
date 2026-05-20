#include "udp.h"
#include <arpa/inet.h>
#include <stddef.h>
#include <sys/types.h>

void parse_udp(const uint8_t* buf, size_t len,
               uint16_t* src_port, uint16_t* dst_port) {
    if (len < sizeof(udp_header_t)) return;

    const udp_header_t* hdr = (const udp_header_t*)buf;
    *src_port = ntohs(hdr->src_port);
    *dst_port = ntohs(hdr->dst_port);
}