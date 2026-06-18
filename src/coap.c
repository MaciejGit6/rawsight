#include "coap.h"
#include <stdio.h>

void dissect_coap(const uint8_t* payload, size_t len){
    if(len<4){
        printf(" [CoAP] truncated\n");
        return;
    }
    uint8_t ver = (payload[0] >> 6) & 0x03;
    uint8_t type = (payload[0] >> 4) & 0x03;
    uint8_t tkl = payload[0] & 0x0F;
    uint8_t code = payload[1];
    uint16_t mid = (payload[2] << 8) | payload[3];

    if(ver != 1){
        printf(" [CoAP] bad version %u\n", ver);
        return;
    }

    printf(" [CoAP] type=%u code=%u MID=%u tkl=%u\n", type, code, mid, tkl);
}

