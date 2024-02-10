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
#ifndef NETDISK_SEND_THREAD
#define NETDISK_SEND_THREAD

#include <linux/kthread.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/wait.h>

#include "packet.h"
#include "transaction.h"

typedef struct chunk_request {
  transaction_t* transaction;
  chunk_t* chunk;
  struct list_head list;
} chunk_request_t;

void send_thread_start(session_t* session);
void enqueue_chunk(transaction_t* transaction, chunk_t* chunk);
void send_chunk_request(session_t* session, transaction_t* trans, chunk_t* chunk);
void send_thread_stop(session_t* session);

#endif  // SEND_THREAD_H