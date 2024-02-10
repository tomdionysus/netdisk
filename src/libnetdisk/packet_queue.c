//
// netdiskd packet queue
//
// Copyright (C) Tom Cully 2024
// Licensed under the MIT License (see LICENSE in root of project)
//
#include "packet_queue.h"

// Function to allocate and initialize a queue
packet_queue_t* packet_queue_allocate(int32_t max_depth) {
  packet_queue_t* queue = malloc(sizeof(packet_queue_t));
  if (!queue) return NULL;

  queue->head = NULL;
  queue->tail = NULL;
  queue->size = 0;
  queue->max_depth = max_depth;

  pthread_mutex_init(&queue->mutex, NULL);
  pthread_cond_init(&queue->not_empty, NULL);
  pthread_cond_init(&queue->not_full, NULL);

  return queue;
}

// Function to enqueue a packet - blocks if the queue is full
int packet_queue_enqueue(packet_queue_t* queue, packet_header_t* header, uint8_t* data) {
  packet_queue_node_t* new_node = malloc(sizeof(packet_queue_node_t));
  if (!new_node) return PACKET_QUEUE_NOMEM;

  new_node->header = header;
  new_node->data = data;
  new_node->next = NULL;

  pthread_mutex_lock(&queue->mutex);

  pthread_cond_wait(&queue->not_full, &queue->mutex);

  // Return NULL if full (SIGINT, etc)
  if (queue->size >= queue->max_depth) {
    pthread_mutex_unlock(&queue->mutex);
    return PACKET_QUEUE_SIGINT;
  }

  if (queue->tail) {
    queue->tail->next = new_node;
  } else {
    queue->head = new_node;
  }
  queue->tail = new_node;
  queue->size++;

  pthread_cond_signal(&queue->not_empty);
  pthread_mutex_unlock(&queue->mutex);

  return PACKET_QUEUE_OK;
}

// Function to dequeue a packet - blocks if the queue is empty
int packet_queue_dequeue(packet_queue_t* queue, packet_header_t** header, uint8_t** data) {
  pthread_mutex_lock(&queue->mutex);

  // Wait for not empty
  pthread_cond_wait(&queue->not_empty, &queue->mutex);

  // Return NULL if empty (SIGINT, etc)
  if (queue->size == 0) {
    pthread_mutex_unlock(&queue->mutex);
    return PACKET_QUEUE_SIGINT;
  }

  packet_queue_node_t* node = queue->head;
  *header = node->header;
  *data = node->data;
  queue->head = queue->head->next;

  if (queue->head == NULL) {
    queue->tail = NULL;
  }
  queue->size--;

  free(node);

  pthread_cond_signal(&queue->not_full);
  pthread_mutex_unlock(&queue->mutex);

  return PACKET_QUEUE_OK;
}

// Function to release all packets in the queue
void packet_queue_free_all_packets(packet_queue_t* queue) {
  pthread_mutex_lock(&queue->mutex);

  packet_queue_node_t* current = queue->head;
  while (current) {
    packet_queue_node_t* node = current;
    current = current->next;
    if (node->header) free(node->header);
    if (node->data) free(node->data);
    free(node);
  }

  queue->head = NULL;
  queue->tail = NULL;
  queue->size = 0;

  pthread_mutex_unlock(&queue->mutex);
}

// Function to release the queue resources
void packet_queue_free(packet_queue_t* queue) {
  packet_queue_free_all_packets(queue);

  pthread_mutex_destroy(&queue->mutex);
  pthread_cond_destroy(&queue->not_empty);
  pthread_cond_destroy(&queue->not_full);

  free(queue);
}