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
#ifndef NETDISK_MODULE
#define NETDISK_MODULE

#include <linux/net.h>
#include <linux/rbtree.h>
#include <linux/socket.h>
#include <net/sock.h>

#include "packet_kernel.h"

typedef struct netdisk_config {
  // Parameters
  struct sockaddr_in address;
  u16 port;
  u8 key[NETDISK_KEY_SIZE];
  char *devicename;
} netdisk_config_t;

int load_parameters(void);

#endif