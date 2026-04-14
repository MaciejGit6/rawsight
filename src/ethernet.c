
void mac_to_str(const uint8_t* mac, char* out, size_t out_len);

const uint8_t* parse_ethernet(const uint8_t* buf, ssize_t len, char* src_mac, char* dst_mac, uint16_t* ethertype){
    if(len < ETH_HLEN){
        return NULL;
    }
    eth_header_t* eth_head = (eth_header_t*)buf;
    
}



