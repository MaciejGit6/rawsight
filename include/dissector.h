#ifndef DISSECTOR_H
#define DISSECTOR_H

#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char    src_mac[18];
    char    dst_mac[18];
    char    src_ip[INET_ADDRSTRLEN];
    char    dst_ip[INET_ADDRSTRLEN];
    uint8_t protocol;     //IPPROTO_TCP / UDP / ICMP or 0 for ARP
    uint16_t src_port;
    uint16_t dst_port;
    size_t   length;
    char info[256]; //description from CoAP/DTLS dissector
} DissectedPacket;

/*Returns 1 on success 0 if the frame was too short or unsupported*/
int dissect_packet(const uint8_t* buf, ssize_t len, DissectedPacket* out);

#ifdef __cplusplus
}
#endif

#endif