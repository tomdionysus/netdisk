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
// This is a heavily modified version of tiny-AES-c 
// (https://github.com/kokke/tiny-AES-c)
//
#ifndef NETDISK_UDP_SOCKET
#define NETDISK_UDP_SOCKET

#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/time.h>
#include <linux/wait.h>
#include <net/sock.h>

int create_udp_socket(void);
int release_udp_socket(void);
int send_udp_packet(const char *buf, size_t len, const struct sockaddr_in *to);
int receive_udp_packet(char *buffer, size_t buffer_size, struct sockaddr_in *src_addr);
wait_queue_head_t* get_socket_wait_queue(void);
bool socket_receive_queue_empty(void);

#endif