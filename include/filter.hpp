#pragma once 
#include "packet.hpp"



class Filter{
public:
    Filter() = default;

    void enable_tcp() = {m_tcp = true;}
    void enable_udp() {m_udp = true;}
    void set_ip(const std::string& ip) { m_target_ip = ip;}

    bool matches(const Packet& p)const;

private:
    bool m_tcp = false;
    bool m_udp = false;


    std::string m_target_ip = "";

}