// converts a 6-byte MAC array to a readable "aa:bb:cc:dd:ee:ff" string
// hint: use snprintf with %02x for each byte
void mac_to_str(const uint8_t* mac, char* out, size_t out_len);

// parses the ethernet header from raw bytes
// returns a pointer to the payload (bytes after the ethernet header)
// returns NULL if the frame is too short
// hint: cast buf to eth_header_t*, check len >= ETH_HLEN
const uint8_t* parse_ethernet(const uint8_t* buf, ssize_t len, char* src_mac, char* dst_mac, uint16_t* ethertype){
    if(len < ETH_HLEN){
        return NULL;
    }
    eth_header_t* eth_head = (eth_header_t*)buf;
    
}

1. check len >= ETH_HLEN, return NULL if too short
2. cast buf to eth_header_t*
3. convert src and dst MAC to strings using mac_to_str
4. read ethertype — remember ntohs() for byte order
5. return buf + ETH_HLEN  (pointer to payload)

