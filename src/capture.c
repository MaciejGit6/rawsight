#include "capture.h"
#include <stdio.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/filter.h>

static volatile sig_atomic_t g_running = 1;

static void handle_sigint(int sig) {
    (void)sig;
    g_running = 0;
}



#define MAX_EVENTS  10
#define BUFFER_SIZE 65536


int open_raw_socket(const char* iface) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("[-] socket() failed - are you running as root?");
        return -1;
    }

    // bind to the specific interface instead of capturing on all of them
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("[-] ioctl SIOCGIFINDEX failed - does that interface exist?");
        close(sock);
        return -1;
    }

    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family   = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex  = ifr.ifr_ifindex;

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("[-] bind() failed");
        close(sock);
        return -1;
    }

    return sock;
}

void capture_loop(int sock, PacketCallback cb) {
    signal(SIGINT, handle_sigint);
    int epfd = epoll_create1(0);
    struct epoll_event ev, events[MAX_EVENTS];

    ev.events  = EPOLLIN;
    ev.data.fd = sock;
    epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev);

    uint8_t buffer[BUFFER_SIZE];

    printf("[*] Capturing... Press Ctrl+C to stop.\n\n");

    while (g_running) {
        int n = epoll_wait(epfd, events, MAX_EVENTS, 500);
        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == sock) {
                ssize_t len = recv(sock, buffer, BUFFER_SIZE, 0);
                if (len > 0 && cb != NULL) {
                    cb(buffer, len);
                }
            }
        }
    }
    printf("\n[*] Shutting down. \n");
    close(epfd);

    close(epfd);
}



int attach_bpf_filter(int sock, const char* proto) {
    if (!proto) return 0; 

    
    struct sock_filter tcp_filter[] = {
        { 0x28, 0, 0, 0x0000000c }, 
        { 0x15, 0, 4, 0x00000800 }, 
        { 0x30, 0, 0, 0x00000017 }, 
        { 0x15, 0, 2, 0x00000006 }, 
        { 0x28, 0, 0, 0x00000000 }, 
        { 0x6,  0, 0, 0x00040000 }, 
        { 0x6,  0, 0, 0x00000000 }, 
    };
    struct sock_filter udp_filter[] = {
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 4, 0x00000800 },
        { 0x30, 0, 0, 0x00000017 },
        { 0x15, 0, 2, 0x00000011 }, 
        { 0x28, 0, 0, 0x00000000 },
        { 0x6,  0, 0, 0x00040000 },
        { 0x6,  0, 0, 0x00000000 },
    };
    struct sock_filter icmp_filter[] = {
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 4, 0x00000800 },
        { 0x30, 0, 0, 0x00000017 },
        { 0x15, 0, 2, 0x00000001 }, 
        { 0x28, 0, 0, 0x00000000 },
        { 0x6,  0, 0, 0x00040000 },
        { 0x6,  0, 0, 0x00000000 },
    };

    struct sock_fprog prog;

    if (strcmp(proto, "tcp") == 0) {
        prog.len    = sizeof(tcp_filter) / sizeof(tcp_filter[0]);
        prog.filter = tcp_filter;
    } else if (strcmp(proto, "udp") == 0) {
        prog.len    = sizeof(udp_filter) / sizeof(udp_filter[0]);
        prog.filter = udp_filter;
    } else if (strcmp(proto, "icmp") == 0) {
        prog.len    = sizeof(icmp_filter) / sizeof(icmp_filter[0]);
        prog.filter = icmp_filter;
    } else {
        fprintf(stderr, "[-] Unknown protocol filter: %s\n", proto);
        return -1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0) {
        perror("[-] SO_ATTACH_FILTER failed");
        return -1;
    }

    printf("[*] BPF filter attached: %s only\n", proto);
    return 0;
}