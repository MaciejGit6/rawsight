#ifndef CAPTURE_H
#define CAPTURE_H
#include <stdint.h>
#include <sys/types.h>


#ifdef __cplusplus
extern "C"{
#endif

typedef void (*PacketCallback){
    const char* src_mac;
    const char* dst_mac,
    const char* src_ip,
    const char* dst_ip,

    uint8_t protocol,
    uint16_t src_port,
    uint16_t dst_port,
    size_t length
};


int open_raw_socket(const char* iface);
void capture_loop(int sock, Packetcallback cb);

#ifdef __cplusplus
}
#endif 
#endif
