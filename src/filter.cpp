#include "filter.hpp"
#include <cstring>

bool Filter::matches(const Packet& p) const {
    if (m_tcp_only && p.protocol != 6 /*IPPROTO_TCP*/) return false;
    if (m_udp_only && p.protocol != 17 /*IPPROTO_UDP*/) return false;

    if (!m_target_ip.empty()) {
        if (p.src_ip != m_target_ip && p.dst_ip != m_target_ip)
            return false;
    }

    return true;
}