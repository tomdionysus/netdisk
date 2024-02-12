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
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/mutex.h>
#include <linux/cond.h>

#include "packet_queue.h"

// Function to allocate and initialize a queue
packet_queue_t* packet_queue_allocate(int32_t max_depth) {
    packet_queue_t* queue = kmalloc(sizeof(packet_queue_t), GFP_KERNEL);
    if (!queue) return NULL;

    memset(queue, 0, sizeof(packet_queue_t));

    queue->head = NULL;
    queue->tail = NULL;
    queue->size = 0;
    queue->max_depth = max_depth;

    mutex_init(&queue->mutex);
    init_waitqueue_head(&queue->not_empty);
    init_waitqueue_head(&queue->not_full);

    return queue;
}

// Function to enqueue a packet - blocks if the queue is full
int packet_queue_enqueue(packet_queue_t* queue, uint8_t* data, uint32_t length) {
    packet_queue_node_t* new_node = kmalloc(sizeof(packet_queue_node_t), GFP_KERNEL);
    if (!new_node) return PACKET_QUEUE_NOMEM;

    new_node->data = data;
    new_node->length = length;
    new_node->next = NULL;

    mutex_lock(&queue->mutex);

    while (queue->size >= queue->max_depth) {
        mutex_unlock(&queue->mutex);
        wait_event(queue->not_full, (queue->size < queue->max_depth));
        mutex_lock(&queue->mutex);
    }

    if (queue->tail) {
        queue->tail->next = new_node;
    } else {
        queue->head = new_node;
    }
    queue->tail = new_node;
    queue->size++;

    wake_up(&queue->not_empty);
    mutex_unlock(&queue->mutex);

    return PACKET_QUEUE_OK;
}

// Function to dequeue a packet - blocks if the queue is empty
int packet_queue_dequeue(packet_queue_t* queue, uint8_t** data, uint32_t* length) {
    mutex_lock(&queue->mutex);

    while (queue->size == 0) {
        mutex_unlock(&queue->mutex);
        wait_event(queue->not_empty, (queue->size > 0));
        mutex_lock(&queue->mutex);
    }

    packet_queue_node_t* node = queue->head;
    *data = node->data;
    *length = node->length;
    queue->head = queue->head->next;

    if (queue->head == NULL) {
        queue->tail = NULL;
    }
    queue->size--;

    kfree(node);

    wake_up(&queue->not_full);
    mutex_unlock(&queue->mutex);

    return PACKET_QUEUE_OK;
}

// Function to release all packets in the queue
void packet_queue_free_all_packets(packet_queue_t* queue) {
    mutex_lock(&queue->mutex);

    packet_queue_node_t* current = queue->head;
    while (current) {
        packet_queue_node_t* node = current;
        current = current->next;
        kfree(node->data);
        kfree(node);
    }

    queue->head = NULL;
    queue->tail = NULL;
    queue->size = 0;

    mutex_unlock(&queue->mutex);
}

// Function to release the queue resources
void packet_queue_free(packet_queue_t* queue) {
    packet_queue_free_all_packets(queue);

    mutex_destroy(&queue->mutex);

    kfree(queue);
}
