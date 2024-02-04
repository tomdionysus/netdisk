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
#include "transaction.h"

struct rb_root trans_tree = RB_ROOT;  // Global transaction tree

// Helper function to insert a transaction into the global transaction tree
static void insert_transaction(transaction_t *trans) {
  struct rb_node **new = &(trans_tree.rb_node), *parent = NULL;

  while (*new) {
    transaction_t *this = container_of(*new, transaction_t, node);
    parent = *new;
    if (trans->id < this->id)
      new = &((*new)->rb_left);
    else if (trans->id > this->id)
      new = &((*new)->rb_right);
    else
      return;  // Duplicate id
  }

  rb_link_node(&trans->node, parent, new);
  rb_insert_color(&trans->node, &trans_tree);
}

transaction_t *create_transaction(u64 id, struct request *rq) {
  transaction_t *trans = kmalloc(sizeof(transaction_t), GFP_KERNEL);
  if (!trans) return NULL;

  trans->id = id;
  trans->request = rq;

  trans->total_chunks = 0;
  trans->total_bytes = 0;
  trans->completed_chunks = 0;
  trans->completed_bytes = 0;

  trans->chunk_tree = RB_ROOT;
  insert_transaction(trans);
  return trans;
}

transaction_t *find_transaction(u64 id) {
  struct rb_node *node = trans_tree.rb_node;

  while (node) {
    transaction_t *trans = container_of(node, transaction_t, node);

    if (id < trans->id)
      node = node->rb_left;
    else if (id > trans->id)
      node = node->rb_right;
    else
      return trans;
  }
  return NULL;
}

static void release_all_chunks(transaction_t *trans) {
  struct rb_node *next, *node = rb_first(&trans->chunk_tree);
  while (node) {
    chunk_t *chunk = container_of(node, chunk_t, node);
    next = rb_next(node);
    rb_erase(node, &trans->chunk_tree);
    kfree(chunk);
    node = next;
  }
}

void release_transaction(u64 id) {
  transaction_t *trans = find_transaction(id);
  if (!trans) return;
  release_all_chunks(trans);
  rb_erase(&trans->node, &trans_tree);
  kfree(trans);
}

void release_all_transactions(void) {
  struct rb_node *next, *node = rb_first(&trans_tree);
  while (node) {
    transaction_t *trans = container_of(node, transaction_t, node);
    next = rb_next(node);
    rb_erase(node, &trans_tree);
    release_all_chunks(trans);
    kfree(trans);
    node = next;
  }
}

// Helper function to insert a chunk into a transaction's chunk tree
static void insert_chunk(transaction_t *trans, chunk_t *chunk) {
  struct rb_node **new = &(trans->chunk_tree.rb_node), *parent = NULL;

  while (*new) {
    chunk_t *this = container_of(*new, chunk_t, node);
    parent = *new;
    if (chunk->block_id < this->block_id)
      new = &((*new)->rb_left);
    else if (chunk->block_id > this->block_id)
      new = &((*new)->rb_right);
    else
      return;  // Duplicate block_id
  }

  trans->total_chunks++;
  trans->total_bytes += chunk->size;

  rb_link_node(&chunk->node, parent, new);
  rb_insert_color(&chunk->node, &trans->chunk_tree);
}

chunk_t *create_chunk(transaction_t *trans, u32 block_id, u8 *buffer, u32 size) {
  chunk_t *chunk = kmalloc(sizeof(chunk_t), GFP_KERNEL);
  if (!chunk) return NULL;

  chunk->block_id = block_id;
  chunk->buffer = buffer;
  chunk->size = size;
  insert_chunk(trans, chunk);
  return chunk;
}

chunk_t *find_chunk(transaction_t *trans, u32 block_id) {
  struct rb_node *node = trans->chunk_tree.rb_node;

  while (node) {
    chunk_t *chunk = container_of(node, chunk_t, node);

    if (block_id < chunk->block_id)
      node = node->rb_left;
    else if (block_id > chunk->block_id)
      node = node->rb_right;
    else
      return chunk;
  }
  return NULL;
}

void release_chunk(transaction_t *trans, u32 block_id) {
  chunk_t *chunk = find_chunk(trans, block_id);
  if (!chunk) return;

  trans->completed_bytes += chunk->size;
  trans->completed_chunks++;

  rb_erase(&chunk->node, &trans->chunk_tree);
  kfree(chunk);
}
