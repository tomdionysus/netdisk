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
#ifndef NETDISK_PACKET_QUEUE
#define NETDISK_PACKET_QUEUE

#include <linux/mutex.h>
#include <linux/cond.h>
#include <linux/slab.h>

#include "shared/packet.h"

// Define the node structure for queue
typedef struct packet_queue_node {
    uint8_t* data;
    uint32_t length;
    struct packet_queue_node* next;
} packet_queue_node_t;

// Define the packet queue structure
typedef struct {
    packet_queue_node_t* head;
    packet_queue_node_t* tail;
    int32_t size;
    int32_t max_depth;
    struct mutex mutex;
    wait_queue_head_t not_empty;
    wait_queue_head_t not_full;
} packet_queue_t;

#define PACKET_QUEUE_OK 0
#define PACKET_QUEUE_SIGINT 1
#define PACKET_QUEUE_NOMEM 2

packet_queue_t* packet_queue_allocate(int32_t max_depth);
int packet_queue_enqueue(packet_queue_t* queue, uint8_t* data, uint32_t length);
int packet_queue_dequeue(packet_queue_t* queue,  uint8_t** data, uint32_t* length);
void packet_queue_free_all_packets(packet_queue_t* queue);
void packet_queue_free(packet_queue_t* queue);

#endif
