//
// netdiskd packet queue
//
// Copyright (C) Tom Cully 2024
// Licensed under the MIT License (see LICENSE in root of project)
//
#ifndef NETDISK_PACKET_QUEUE
#define NETDISK_PACKET_QUEUE

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>

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
  pthread_mutex_t mutex;
  pthread_cond_t not_empty;
  pthread_cond_t not_full;
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