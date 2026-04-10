#pragma once

#include "packet.hpp"

class Filter {
public:
    Filter() = default;

    void enable_tcp_only() { m_tcp_only = true; }
    void enable_udp_only() { m_udp_only = true; }
    void set_ip(const std::string& ip) { m_target_ip = ip; }

    bool matches(const Packet& p) const;



private:

    bool        m_tcp_only  = false;
    bool        m_udp_only  = false;
    std::string m_target_ip = "";
};