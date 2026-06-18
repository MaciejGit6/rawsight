#pragma once 
#include <stdint.h>
#include <stddef.h>

#define COAP_PORT 5683
//My notes:
//CoAP Constrained Application interface 
//used when HTTP is too heavy 

void dissect_coap(const uint8_t* payload, size_t len);