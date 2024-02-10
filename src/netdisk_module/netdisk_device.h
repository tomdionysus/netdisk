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
#ifndef NETDISK_DEVICE
#define NETDISK_DEVICE

#include <linux/blk-mq.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/hdreg.h>
#include <linux/inet.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <net/sock.h>

#include "packet.h"

#define TOTAL_SECTORS (100 * 1024 * 1024 / 512)

struct netdisk {
  sector_t capacity_sectors;
  struct blk_mq_tag_set *tag_set;
  struct gendisk *disk;
  struct socket *tcp_socket;

  bool _disk_added;
};

int create_netdisk_device(char *devicename, struct socket *tcp_socket);
void netdisk_complete_chunk(session_t *session, packet_header_t *header);
void netdisk_error_chunk(u64 trans_id, u64 block_id, u8 error);
void error_all_transactions(void);
int release_netdisk_device(void);

#endif