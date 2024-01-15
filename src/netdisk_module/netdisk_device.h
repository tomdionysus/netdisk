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

#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>
#include <linux/blk-mq.h>
#include <linux/hdreg.h>
#include <linux/inet.h>

#include "transaction.h"

#define TOTAL_SECTORS 204800

struct netdisk {
    sector_t capacity_sectors;
    u8 *data;   // Data buffer to emulate real storage device
    struct blk_mq_tag_set *tag_set;
    struct gendisk *disk;

    bool _disk_added;
};

int create_netdisk_device(char *devicename);
int release_netdisk_device(void);

#endif