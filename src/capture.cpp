#include "capture.h"
#include <stdio.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <unistd.h>

#define MAX_EVENTS  10
#define BUFFER_SIZE 65536

int open_raw_socket(const char* iface) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("[-] socket() failed - are you running as root?");
        return -1;

    }

    return sock;
}

void capture_loop(int sock, PacketCallback cb) {

    
    int epfd = epoll_create1(0);
    struct epoll_event ev, events[MAX_EVENTS];

    ev.events  = EPOLLIN;
    ev.data.fd = sock;
    epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev);

    uint8_t buffer[BUFFER_SIZE];

    printf("[*] Capturing... Press Ctrl+C to stop.\n\n");


    while (1) {
        int n = epoll_wait(epfd, events, MAX_EVENTS, -1);
        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == sock) {
                ssize_t len = recv(sock, buffer, BUFFER_SIZE, 0);
                if (len > 0 && cb != NULL) {
                    cb(buffer, len);
                }
            }
        }
    }

    close(epfd);
}