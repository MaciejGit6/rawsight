#ifndef CAPTURE_H
#define CAPTURE_H

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif



/* Return 1 to keep capturing, 0 to stop the capture/read loop. */
typedef int (*PacketCallback)(const uint8_t* buf, ssize_t len);

int  open_raw_socket(const char* iface);
void capture_loop(int sock, PacketCallback cb);

int attach_bpf_filter(int sock, const char* proto);

#ifdef __cplusplus
}
#endif

#endif