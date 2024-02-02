//
// /dev/netdisk device driver
// 
// Copyright (C) 2024 Tom Cully
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
//
// Original by Oleg Kutkov (https://olegkutkov.me/2020/02/10/linux-block-device-driver)
// Adapted for linux-6.6.7-0-lts by Tom Cully 2023
//
// Tested under linux 6.6.7-0-lts
//
#include "module.h"
#include "udp_socket.h"

// Global Config
extern netdisk_config_t config;

// UDP Socket
static struct socket *udp_socket;
static DEFINE_MUTEX(socket_mutex);

int create_udp_socket(void) {
    struct sockaddr_in addr;
    int ret;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(0);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    ret = sock_create_kern(&init_net, AF_INET, SOCK_DGRAM, IPPROTO_UDP, &udp_socket);
    if (ret < 0) {
        printk(KERN_ERR "netdisk: failed to create UDP socket\n");
        return ret;
    }

    ret = kernel_bind(udp_socket, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        printk(KERN_ERR "netdisk: failed to bind UDP socket\n");
        sock_release(udp_socket);
        return ret;
    }

    return 0;
}

int release_udp_socket(void) {
    if (udp_socket) {
        sock_release(udp_socket);
        udp_socket = NULL;
    }
    return 0;
}

int send_udp_packet(const char *buf, size_t len, const struct sockaddr_in *to) {

    struct msghdr msg;
    struct kvec iov;
    int size;

    iov.iov_base = (void *)buf;
    iov.iov_len = len;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)to;
    msg.msg_namelen = sizeof(struct sockaddr_in);

    mutex_lock(&socket_mutex);
    size = kernel_sendmsg(udp_socket, &msg, &iov, 1, len);
    if (size < 0) {
        printk(KERN_ALERT "netdisk: Failed to send UDP packet\n");
    }
    mutex_unlock(&socket_mutex);

    return size;
}

int receive_udp_packet(char *buffer, size_t buffer_size, struct sockaddr_in *src_addr) {

    struct msghdr msg;
    struct kvec iov;
    int size;

    iov.iov_base = buffer;
    iov.iov_len = buffer_size;

    memset(src_addr, 0, sizeof(struct sockaddr_in));
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = src_addr;
    msg.msg_namelen = sizeof(struct sockaddr_in);

    mutex_lock(&socket_mutex);
    size = kernel_recvmsg(udp_socket, &msg, &iov, 1, buffer_size, 0);
    mutex_unlock(&socket_mutex);

    if (size < 0) {
         printk(KERN_ALERT "netdisk: Failed to send UDP packet\n");
    }

    return size;
}

wait_queue_head_t* get_socket_wait_queue(void) {
    return sk_sleep(udp_socket->sk);
}

bool socket_receive_queue_empty(void) {
    mutex_lock(&socket_mutex);
    bool empty = skb_queue_empty(&udp_socket->sk->sk_receive_queue);
    mutex_unlock(&socket_mutex);
    return empty;
}