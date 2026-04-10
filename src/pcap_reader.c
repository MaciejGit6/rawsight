#include "pcap_reader.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PCAP_MAGIC      0xa1b2c3d4
#define PCAP_MAGIC_SWAP 0xd4c3b2a1

typedef struct {
    uint32_t magic;


    uint16_t major;
    uint16_t minor;

    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;

} pcap_file_header_t;



typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;

} pcap_packet_header_t;


int read_pcap_file(const char* filepath, PacketCallback cb) {
    FILE* f = fopen(filepath, "rb");
    if (!f) {
        perror("[-] could not open pcap file");
        return -1;
    }

    pcap_file_header_t fhdr;
    if (fread(&fhdr, sizeof(fhdr), 1, f) != 1) {
        printf("[-] failed to read pcap header\n");
        fclose(f);
        return -1;
    }

    if (fhdr.magic != PCAP_MAGIC && fhdr.magic != PCAP_MAGIC_SWAP) {
        
        printf("[-] not a valid pcap file (magic: 0x%x)\n", fhdr.magic);
        fclose(f);
        return -1;
    }

    printf("[+] pcap file opened. link type: %u\n\n", fhdr.network);

    uint8_t* buf = malloc(65536);
    pcap_packet_header_t phdr;
    int count = 0;

    while (fread(&phdr, sizeof(phdr), 1, f) == 1) {
        if (phdr.incl_len > 65536) break;
        if (fread(buf, 1, phdr.incl_len, f) != phdr.incl_len) break;

        if (cb != NULL) cb(buf, (ssize_t)phdr.incl_len);
        count++;
    }


    printf("\n[+] done. %d packets processed.\n", count);

    free(buf);
    fclose(f);

    return 0;
}