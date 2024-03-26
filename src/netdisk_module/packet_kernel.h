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
#ifndef PACKET
#define PACKET

#include <linux/blk-mq.h>
#include <linux/ktime.h>
#include <linux/net.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/timekeeping.h>
#include <linux/types.h>
#include <net/sock.h>

#include "aes.h"
#include "shared/packet.h"
#include "transaction.h"
#include "util.h"

#pragma pack(push, 1)

typedef struct session {
  struct socket* socket_fd;
  struct sockaddr_in remote_addr;
  uint8_t state;
  struct AES_ctx* aes_context;
  uint64_t node_id;
  char address_str[32];
  uint8_t* buffer;
} session_t;

#pragma pack(pop)

int packet_create_client_socket(struct socket** tcp_socket, struct sockaddr_in* addr);
int packet_destroy_socket(struct socket* tcp_socket);

ssize_t packet_recv(struct socket* tcp_socket, uint8_t* buffer, size_t size, int timeout_ms);
ssize_t packet_send(struct socket* tcp_socket, uint8_t* buffer, size_t size);

#endif
