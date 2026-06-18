#include "coap.h"
#include <stdio.h>
#include <string.h>

#define COAP_OPT_URI_PATH 11
#define COAP_OPT_URI_QUERY 15


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
        case 0x41: return "Created";
        case 0x44: return "Changed";
        case 0x45: return "Content";
        case 0x80: return "Bad Requst";
        case 0x84: return "Not Found";
        case 0xa0: return "Internal Error";
        default: return NULL;

    }
}

static int coap_ext(uint8_t nibble, const uint8_t** pp, const uint8_t* end){
    if(nibble < 13) return nibble;
    if(nibble == 13){
        if(*pp >= end)return -1;
        int v = **pp + 13;
        (*pp)++;
        return v;
    }
    if(nibble == 14){
        if(end - *pp < 2) return -1;
        int v = ((*pp)[0] << 8 | (*pp)[1]) + 269;
        *pp += 2;
        return v;
    }
    return -1;
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
    uint8_t det = code & 0x1F;
    const char* name = coap_code_name(code);

    if(name){
        printf(" [CoAP] %s %u.%02u (%s) MID=%u tkl=%d\n",
            coap_type(type), cls, det, name, mid, tkl);
        
    }else{
        printf("  [CoAP] %s %u.%02u MID=%u tkl=%u\n",
               coap_type(type), cls, det, mid, tkl);
    }

    const uint8_t* p = payload + 4 + tkl;
    const uint8_t* end = payload + len;
    if(p > end) return;

    char path[256]; path[0] = '\0';
    char query[256]; query[0] = '\0';
    int opt_num = 0;

    while (p < end){
        if(*p == 0xFF) break;
        uint8_t d = *p >> 4;
        uint8_t l = *p & 0x0F;
        p++;

        int delta = coap_ext(d, &p, end);
        int olen = coap_ext(l, &p, end);
        if(delta < 0 || olen < 0) break;
        if(p + olen > end) break;

        opt_num += delta;
        if(opt_num == COAP_OPT_URI_PATH){
            size_t u = strlen(path);
            if(u+1 + (size_t)olen + 1 < sizeof(path)){
                path[u] = '/';
                memcpy(path + u + 1, p, olen);
                path[u + 1 + olen] = '\0';

            }
        }else if(opt_num == COAP_OPT_URI_QUERY){
            size_t u = strlen(query);
            const char* sep = (u == 0) ? "" : "&";
            if(u + strlen(sep) + (size_t)olen + 1 < sizeof(query)){
                memcpy(query + u, sep, strlen(sep));
                memcpy(query + u + strlen(sep), p, olen);
                query[u + strlen(sep) + olen] = '\0';
            }
        }
        p += olen;
    }

    if(path[0])printf("\tUri-Path: %s\n",path);
    if(query[0])printf("\tUri-Query: %s\n", query);
}

