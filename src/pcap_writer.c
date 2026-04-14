#include "pcap_writer.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>

#define PCAP_MAGIC    0xa1b2c3d4
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4
#define PCAP_LINKTYPE_EN10MB 1  

typedef struct {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} __attribute__((packed)) PcapGlobalHeader;

typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} __attribute__((packed)) PcapRecordHeader;

struct PcapWriter {
    FILE* f;
};

PcapWriter* pcap_writer_open(const char* path) {
    PcapWriter* w = malloc(sizeof(PcapWriter));
    w->f = fopen(path, "wb");
    if (!w->f) { free(w); return NULL; }

    PcapGlobalHeader gh = {
        .magic         = PCAP_MAGIC,
        .version_major = PCAP_VERSION_MAJOR,
        .version_minor = PCAP_VERSION_MINOR,
        .thiszone      = 0,
        .sigfigs       = 0,
        .snaplen       = 65535,
        .network       = PCAP_LINKTYPE_EN10MB,
    };
    fwrite(&gh, sizeof(gh), 1, w->f);
    return w;
}

void pcap_writer_write(PcapWriter* w, const uint8_t* data, size_t len) {
    struct timeval tv;
    gettimeofday(&tv, NULL);

    PcapRecordHeader rh = {
        .ts_sec   = (uint32_t)tv.tv_sec,
        .ts_usec  = (uint32_t)tv.tv_usec,
        .incl_len = (uint32_t)len,
        .orig_len = (uint32_t)len,
    };
    fwrite(&rh, sizeof(rh), 1, w->f);
    fwrite(data, len, 1, w->f);
}

void pcap_writer_close(PcapWriter* w) {
    if (w) { fclose(w->f); free(w); }
}