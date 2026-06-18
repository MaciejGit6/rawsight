#include "coap.h"
#include <stdio.h>

static const char* coap_type(uint8_t t){
    switch(t){
        case 0: return "CON";
        case 1: return "NON";
        case 2: return "ACK";
        case 3: return "RST";
        default: return "?";
    }

}

static const char* coap_code_name(uint8_t code){
    switch(code){
        case 0x00: return "Empty";
        case 0x01: return "GET";
        case 0x02: return "POST";
        case 0x03: return "PUT";
        case 0x04: return "DELETE";
        case 0x41: return "Created":
        case 0x44: return "Changed";
        case 0x45: return "Content";
        case 0x80: return "Bad Requst";
        case 0x84: return "Not Found";
        case 0xa0: return "Internal Error";
        default: return NULL;

    }
}

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

    uint8_t cls = code >> 5;
    uint8_t = code & 0x1F;
    const char* name = coap_code_name(code);

    if(name){
        printf(" [CoAP] %s %u.%02u (%s) MID=%u tkl=%d\n",
            coap_type(type), cls, det, name, mid, tkl);
        
    }else{
        printf("  [CoAP] %s %u.%02u MID=%u tkl=%u\n",
               coap_type(type), cls, det, mid, tkl);
    }
}

