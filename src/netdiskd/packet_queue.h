//
// netdiskd packet queue
//
// Copyright (C) Tom Cully 2024
// Licensed under the MIT License (see LICENSE in root of project)
//
#ifndef NETDISK_PACKET_QUEUE
#define NETDISK_PACKET_QUEUE

#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>

#include "packet.h"

// Define the node structure for queue
typedef struct packet {
    packet_header_t* header;
    uint8_t *data;
} packet_t;

// Define the node structure for queue
typedef struct packet_queue_node {
    packet_t* packet;
    struct packet_queue_node* next;
} packet_queue_node_t;

// Define the packet queue structure
typedef struct {
    packet_queue_node_t* head;
    packet_queue_node_t* tail;
    int32_t size;
    int32_t max_depth;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} packet_queue_t;

packet_queue_t* packet_queue_allocate(int32_t max_depth);
void packet_queue_enqueue(packet_queue_t* queue, packet_t* packet);
packet_t* packet_queue_dequeue(packet_queue_t* queue);
void packet_queue_free_all_packets(packet_queue_t* queue);
void packet_queue_free(packet_queue_t* queue);

#endif