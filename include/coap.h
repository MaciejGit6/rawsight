#pragma once 
#include <stdint.h>
#include <stddef.h>

#define COAP_PORT 5683
#define COAPS_PORT 5684
//My notes:
//CoAP Constrained Application interface 
//used when HTTP is too heavy 
//Coaps = COAP over DTLS (coap but secure)

void dissect_coap(const uint8_t* payload, size_t len, char* info, size_t info_len);