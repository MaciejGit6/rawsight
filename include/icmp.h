#pragma once
#include <stdint.h>
#include <stddef.h>

void dissect_icmp(const uint8_t* payload, size_t len);