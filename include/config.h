#pragma once

typedef struct {
    const char* iface;    
    int         max_packets; 
    const char* proto_filter; 
} CaptureConfig;