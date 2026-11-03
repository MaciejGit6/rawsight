cmake_minimum_required(VERSION 3.14)
project(rawsight VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(C_SOURCES
    src/capture.c
    src/ethernet.c
    src/ipv4.c
    src/tcp.c
    src/udp.c
    src/arp.c
    src/icmp.c
    src/coap.c
    src/dissector.c
    src/pcap_reader.c
    src/pcap_writer.c
)

set(CXX_SOURCES
    src/main.cpp
    src/filter.cpp
    src/display.cpp
)

add_executable(rawsight ${C_SOURCES} ${CXX_SOURCES})

target_compile_options(rawsight PRIVATE -Wall -Wextra -g -O0)

option(RAWSIGHT_SANITIZE "build with AddressSanitizer + UBSan" OFF)
if(RAWSIGHT_SANITIZE)
    set(SAN_FLAGS -fsanitize=address,undefined -fno-sanitize-recover=undefined
                  -fno-omit-frame-pointer)
    target_compile_options(rawsight PRIVATE ${SAN_FLAGS})
    target_link_options(rawsight PRIVATE ${SAN_FLAGS})
endif()

target_include_directories(rawsight PRIVATE ${CMAKE_SOURCE_DIR}/include)

# regression tests: ctest --test-dir build
enable_testing()

function(rawsight_test name expect_rc args)
    add_test(NAME ${name}
        COMMAND ${CMAKE_COMMAND}
            -DBIN=$<TARGET_FILE:rawsight>
            "-DARGS=${args}"
            -DEXPECTED=${CMAKE_SOURCE_DIR}/tests/expected/${name}.txt
            -DEXPECT_RC=${expect_rc}
            -P ${CMAKE_SOURCE_DIR}/tests/run_test.cmake
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
endfunction()

rawsight_test(coap            0   "-r coap.pcap")
rawsight_test(coap2           0   "-r coap2.pcap")
rawsight_test(mixed           0   "-r mixed.pcap")
rawsight_test(mixed_tcp       0   "-r mixed.pcap -p tcp")
rawsight_test(mixed_udp       0   "-r mixed.pcap -p udp")
rawsight_test(mixed_icmp      0   "-r mixed.pcap -p icmp")
rawsight_test(mixed_count     0   "-r mixed.pcap -n 2")
rawsight_test(mixed_ip        0   "-r mixed.pcap -f 8.8.8.8")
rawsight_test(bad_proto       1   "-r mixed.pcap -p foo")
rawsight_test(coap_long_uri   0   "-r tests/data/coap_long_uri.pcap")
rawsight_test(coap_padded     0   "-r tests/data/coap_padded.pcap")
rawsight_test(ipv4_fragment   0   "-r tests/data/ipv4_fragment.pcap")
rawsight_test(coap_bigendian  0   "-r tests/data/coap_bigendian.pcap")
rawsight_test(linktype_sll    255 "-r tests/data/linktype_sll.pcap")