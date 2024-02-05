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
#include "send_thread.h"

#include "netdisk_device.h"
#include "packet.h"

extern session_t *session;

static struct task_struct *send_thread = NULL;
static DECLARE_WAIT_QUEUE_HEAD(wait_queue);
static LIST_HEAD(chunk_queue);
static DEFINE_MUTEX(queue_mutex);
static bool thread_running = false;

static int run_send_thread(void *data) {
  chunk_request_t *req;
  while (thread_running || !list_empty(&chunk_queue)) {
    wait_event_interruptible(wait_queue, !list_empty(&chunk_queue) || !thread_running);

    if (!thread_running && list_empty(&chunk_queue)) break;

    mutex_lock(&queue_mutex);
    if (!list_empty(&chunk_queue)) {
      req = list_first_entry(&chunk_queue, chunk_request_t, list);
      list_del(&req->list);
      mutex_unlock(&queue_mutex);

      send_chunk_request(session->socket_fd, &session->tx_aes_context, req->transaction, req->chunk);

      kfree(req);
    } else {
      mutex_unlock(&queue_mutex);
    }
  }

  // Drain the queue
  mutex_lock(&queue_mutex);
  while (!list_empty(&chunk_queue)) {
    req = list_first_entry(&chunk_queue, chunk_request_t, list);
    list_del(&req->list);

    netdisk_error_chunk(req->transaction->id, req->chunk->block_id, -1);

    kfree(req);  // Free the chunk request
  }
  mutex_unlock(&queue_mutex);

  thread_running = false;
  send_thread = NULL;

  return 0;
}

void send_thread_start(void) {
  if (send_thread) {
    printk(KERN_INFO "netdisk: Send thread already started\n");
    return;
  }

  thread_running = true;
  send_thread = kthread_run(run_send_thread, NULL, "netdisk_send_thread");
  if (IS_ERR(send_thread)) {
    printk(KERN_ERR "netdisk: Failed to start send thread\n");
    thread_running = false;
    send_thread = NULL;
  }
}

void enqueue_chunk(transaction_t *trans, chunk_t *chunk) {
  chunk_request_t *req = kmalloc(sizeof(*req), GFP_KERNEL);
  if (!req) {
    printk(KERN_ERR "netdisk: Failed to allocate chunk request\n");
    return;
  }

  req->transaction = trans;
  req->chunk = chunk;
  mutex_lock(&queue_mutex);
  list_add_tail(&req->list, &chunk_queue);
  mutex_unlock(&queue_mutex);
  wake_up(&wait_queue);
}

void send_thread_stop(void) {
  if (!send_thread) {
    printk(KERN_INFO "netdisk: Send thread not running\n");
    return;
  }

  printk(KERN_NOTICE "netdisk: Stopping send thread\n");

  // Set the flag to false to stop the thread and wake it up
  thread_running = false;
  wake_up(&wait_queue);

  // Wait for the thread to finish
  kthread_stop(send_thread);
  send_thread = NULL;
  printk(KERN_NOTICE "netdisk: Stopped send thread\n");
}
