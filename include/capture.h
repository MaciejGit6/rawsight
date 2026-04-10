#ifndef CAPTURE_H
#define CAPTURE_H

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif



typedef void (*PacketCallback)(const uint8_t* buf, ssize_t len);

int  open_raw_socket(const char* iface);
void capture_loop(int sock, PacketCallback cb);

#ifdef __cplusplus
}
#endif

#endif