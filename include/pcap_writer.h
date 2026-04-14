#pragma once
#include <stdint.h>
#include <stddef.h>

typedef struct PcapWriter PcapWriter;

PcapWriter* pcap_writer_open(const char* path);
void        pcap_writer_write(PcapWriter* w, const uint8_t* data, size_t len);
void        pcap_writer_close(PcapWriter* w);