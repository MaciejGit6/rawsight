#include "dissector.h"
#include "ethernet.h"
#include "ipv4.h"
#include "tcp.h"
#include "udp.h"
#include "icmp.h"
#include "arp.h"
#include <string.h>
#include <netinet/in.h>
#include "coap.h"
#include <stdio.h>

int dissect_packet(const uint8_t* buf, ssize_t len, DissectedPacket* out) {
    if (!buf || len <= 0 || !out) return 0;
    memset(out, 0, sizeof(*out));
    out->length = (size_t)len;

    
    uint16_t ethertype = 0;
    const uint8_t* payload = parse_ethernet(buf, len,
                                             out->src_mac, out->dst_mac,
                                             &ethertype);
    if (!payload) return 0;
    size_t payload_len = (size_t)(len - (payload - buf));

    if (ethertype == ETHERTYPE_ARP) {
        out->protocol = 0;   //sentinel for ARP
        dissect_arp(payload, payload_len);
        return 1;
    }

    if (ethertype != ETHERTYPE_IPV4) return 0;  //skipping IPv6 for  now

    const uint8_t* l4 = parse_ipv4(payload, payload_len,
                                    out->src_ip, out->dst_ip,
                                    &out->protocol);
    if (!l4) return 0;
    size_t l4_len = payload_len - (size_t)(l4 - payload);

    switch (out->protocol) {
        case IPPROTO_TCP:
            parse_tcp(l4, l4_len, &out->src_port, &out->dst_port);
            break;
        case IPPROTO_UDP:
            parse_udp(l4, l4_len, &out->src_port, &out->dst_port);
            if(out->src_port == COAP_PORT || out->dst_port == COAP_PORT){
                if(l4_len > 8)
                    dissect_coap(l4 + 8, l4_len - 8);
            }else if(out->src_port == COAPS_PORT || out->dst_port == COAPS_PORT){
                printf(" [DTLS] encrypted CoAP(coaps)\n");
            }
            break;

        case IPPROTO_ICMP:
            dissect_icmp(l4, l4_len);
            break;
    }

    return 1;
}