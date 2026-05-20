cmake_minimum_required(VERSION 3.14)
project(rawsight VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(C_SOURCES
    src/capture.c       # capture.cpp is a stale duplicate, delete it
    src/ethernet.c
    src/ipv4.c
    src/tcp.c
    src/udp.c
    src/arp.c
    src/icmp.c
    src/dissector.c
    src/pcap_reader.c
    src/pcap_writer.c
)

set(CXX_SOURCES
    src/main.cpp
    src/packet.cpp
    src/filter.cpp
    src/display.cpp
)

add_executable(rawsight ${C_SOURCES} ${CXX_SOURCES})

target_compile_options(rawsight PRIVATE -Wall -Wextra -g -O0)

target_include_directories(rawsight PRIVATE ${CMAKE_SOURCE_DIR}/include)