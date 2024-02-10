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
#ifndef NETDISK_TRANSACTION
#define NETDISK_TRANSACTION

#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/types.h>

typedef struct chunk {
  u64 block_id;
  u8* buffer;
  u32 size;
  struct rb_node node;  // Red/Black tree node
} chunk_t;

typedef struct transaction {
  u64 id;
  u32 total_chunks;
  u32 total_bytes;
  u32 completed_chunks;
  u32 completed_bytes;
  struct request* request;
  struct rb_root chunk_tree;  // Red/Black tree root for chunks

  struct rb_node node;  // Red/Black tree node
} transaction_t;

transaction_t* create_transaction(u64 id, struct request* rq);  // Allocate and return a new trasaction with the given id and an empty chunk tree.
transaction_t* find_transaction(u64 id);                        // Return the transaction with the given id or NULL.
void release_transaction(u64 id);                               // Release the given transaction, and release all of its owned chunks

void release_all_transactions(void);

chunk_t* create_chunk(transaction_t* trans, u32 block_id, u8* buffer,
                      u32 size);                          // Allocate and setup a new chunk, add it to the transaction tree, and return it.
chunk_t* find_chunk(transaction_t* trans, u32 block_id);  // Return the chunk with the given block_id or NULL
void release_chunk(transaction_t* trans, u32 block_id);   // Find, remove from the transaction, and release the chunk with the given block_id

#endif