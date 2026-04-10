#ifndef PCAP_READER_H
#define PCAP_READER_H

#include "capture.h"

#ifdef __cplusplus
extern "C" {
#endif

int read_pcap_file(const char* filepath, PacketCallback cb);


#ifdef __cplusplus
}
#endif

#endif