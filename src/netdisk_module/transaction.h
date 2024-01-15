
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
#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/ktime.h>
#include <linux/blk-mq.h>

// Define a structure for each chunk of the transaction
typedef struct chunk {
    u64 block_id;
    void *data;
    size_t size;
    struct rb_node node;

    // Used for deletion
    struct list_head list;
} chunk_t;

// Define the structure for the entire transaction
typedef struct transaction {
    u64 id;
    struct request *orig_rq;
    struct list_head chunks;
    spinlock_t lock;
    struct rb_node node;
    struct rb_root chunk_tree;

    // Used to timeout transactions
    ktime_t timeout;
    struct list_head list;

    u64 total_bytes;
    u64 completed_bytes;
    u64 total_chunks;
    u64 completed_chunks;
} transaction_t;

transaction_t *create_transaction(u64 id, struct request *rq);
int insert_transaction(transaction_t *trans);
transaction_t *find_transaction(u64 id);
void release_transaction(transaction_t *trans);
void _release_transaction(transaction_t *trans, bool locking);

void release_timed_out_transactions(void);

chunk_t* create_chunk(transaction_t *trans, u64 block_id, void *data, size_t size);
int insert_chunk(transaction_t *trans, chunk_t *chk);
chunk_t *find_chunk(transaction_t *trans, u64 block_id);
void remove_chunk(transaction_t *trans, chunk_t *chk);

int create_transaction_registry(void);
int release_transaction_registry(void);

#endif /* TRANSaCTIONS_H */
