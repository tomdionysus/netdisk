#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/list.h>

#include "transaction.h"

static struct rb_root trans_tree = RB_ROOT;
static spinlock_t trans_tree_lock;

// Function to process and release timed out transactions
void release_timed_out_transactions(void) {
    struct rb_node *node;
    transaction_t *trans, *tmp;
    LIST_HEAD(timed_out_transactions);

    int count = 0;
    int timedout = 0;

    spin_lock(&trans_tree_lock);

    // First pass: iterate over the tree and collect transactions that have timed out
    for (node = rb_first(&trans_tree); node; node = rb_next(node)) {
        trans = rb_entry(node, transaction_t, node);
        count++;
        ktime_t now = ktime_get();
        if (ktime_compare(now, trans->timeout) >= 0) {
            list_add_tail(&trans->list, &timed_out_transactions);
            timedout++;
        }
    }

    printk(KERN_DEBUG "netdisk: release_timed_out_transactions: %d transactions, %d timed out\n", count, timedout);

    // Second pass: process and release collected transactions
    list_for_each_entry_safe(trans, tmp, &timed_out_transactions, list) {
        list_del(&trans->list);
        printk(KERN_ALERT "netdisk: transaction timed out %llu/%llu chunks, %llu/%llu bytes (transaction %llu)\n", trans->completed_chunks, trans->total_chunks, trans->completed_bytes, trans->total_bytes, trans->id);
        _release_transaction(trans, false);
    }

    spin_unlock(&trans_tree_lock);
}

transaction_t *create_transaction(u64 id, struct request *rq) {

    printk(KERN_ALERT "netdisk: creating new transaction %llu direction %s\n", id, rq_data_dir(rq) == WRITE ? "WRITE" : "READ");

    transaction_t *trans = vmalloc(sizeof(transaction_t));
    if (!trans) {
        printk(KERN_ALERT "netdisk: out of memory creating new transaction %llu", id);
        return NULL;
    }

    trans->id = id;
    trans->orig_rq = rq;
    trans->chunk_tree = RB_ROOT;

    trans->total_bytes = 0;
    trans->completed_bytes = 0;

    trans->total_chunks = 0;
    trans->completed_chunks = 0;

    // Get the current time
    ktime_t now = ktime_get();

    // Set the timeout to 10 seconds from now
    trans->timeout = ktime_add(now, ktime_set(3, 0));

    INIT_LIST_HEAD(&trans->list);

    spin_lock_init(&trans->lock);

    if (insert_transaction(trans) != 0) {
        vfree(trans);
        return NULL;
    }

    return trans;
}

int insert_transaction(transaction_t *trans) {
    struct rb_node **new = &(trans_tree.rb_node), *parent = NULL;
    
    // Lock the transaction registry
    spin_lock(&trans_tree_lock);

    // Figure out where to put the new node
    while (*new) {
        transaction_t *this = container_of(*new, transaction_t, node);
        parent = *new;
        if (trans->id < this->id)
            new = &((*new)->rb_left);
        else if (trans->id > this->id)
            new = &((*new)->rb_right);
        else {
            // Id already exists
            spin_unlock(&trans_tree_lock);
            printk(KERN_ALERT "netdisk: !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! duplicate transaction id %llu\n", trans->id);
            return -EEXIST;
        }
    }

    // Add the new node to the RB-tree
    rb_link_node(&trans->node, parent, new);
    rb_insert_color(&trans->node, &trans_tree);

    // Unlock the transaction registry
    spin_unlock(&trans_tree_lock);
    return 0;
}

chunk_t* create_chunk(transaction_t *trans, u64 block_id, void *data, size_t size) {
    chunk_t *chk = vmalloc(sizeof(chunk_t));
    if (!chk) return NULL;

    chk->block_id = block_id;
    chk->data = data;
    chk->size = size;

    RB_CLEAR_NODE(&chk->node);

    if (insert_chunk(trans, chk) != 0) {
        vfree(chk);
        return NULL;
    }

    return chk;
}

int insert_chunk(transaction_t *trans, chunk_t *chk) {
    struct rb_node **new = &(trans->chunk_tree.rb_node), *parent = NULL;

    // Lock the transaction chunk tree
    spin_lock(&trans->lock);

    // Figure out where to put the new node
    while (*new) {
        chunk_t *this = container_of(*new, chunk_t, node);
        parent = *new;
        if (chk->block_id < this->block_id) {
            new = &((*new)->rb_left);
        } else if (chk->block_id > this->block_id) {
            new = &((*new)->rb_right);
        } else {
            spin_unlock(&trans->lock);
            printk(KERN_ALERT "netdisk: !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! duplicate chunk id %llu\n", chk->block_id);
            return -EEXIST;
        }
    }

    // Add the new node to the RB-tree
    rb_link_node(&chk->node, parent, new);
    rb_insert_color(&chk->node, &(trans->chunk_tree));

    // Unlock the transaction chunk tree
    spin_unlock(&trans->lock);
    return 0;
}

chunk_t *find_chunk(transaction_t *trans, u64 block_id) {
    struct rb_node *node = trans->chunk_tree.rb_node;

    // Lock the transaction chunk tree
    spin_lock(&trans->lock);

    while (node) {
        chunk_t *chk = container_of(node, chunk_t, node);
        if (block_id < chk->block_id) {
            node = node->rb_left;
        } else if (block_id > chk->block_id) {
            node = node->rb_right;
        } else {
            spin_unlock(&trans->lock);
            return chk; // Found it
        }
    }

    spin_unlock(&trans->lock);
    return NULL;
}

transaction_t *find_transaction(u64 id) {
    struct rb_node *node = trans_tree.rb_node;

    // Lock the transaction registry
    spin_lock(&trans_tree_lock);

    while (node) {
        transaction_t *trans = container_of(node, transaction_t, node);
        if (id < trans->id) {
            node = node->rb_left;
        } else if (id > trans->id) {
            node = node->rb_right;
        } else {
            // Unlock the transaction registry
            spin_unlock(&trans_tree_lock);
            return trans; // Found it
        }
    }

    // Unlock the transaction registry
    spin_unlock(&trans_tree_lock);
    return NULL;
}

void remove_chunk(transaction_t *trans, chunk_t *chk) {
    spin_lock(&trans->lock);

    // Store size in bytes
    u16 size = chk->size;

    // Remove from transaction
    rb_erase(&chk->node, &(trans->chunk_tree));

    // Free chunk
    vfree(chk);

    // Update transaction completed
    trans->completed_chunks++;
    trans->completed_bytes += size;

    // Report completed to request
    blk_update_request(trans->orig_rq, BLK_STS_OK, trans->completed_bytes);

    spin_unlock(&trans->lock);
}

#include <linux/list.h>
#include <linux/slab.h>

void _release_transaction(transaction_t *trans, bool locking) {
    struct rb_node *node;
    chunk_t *chk;
    LIST_HEAD(chunk_list);

    printk(KERN_ALERT "netdisk: notifying blk_update_request for transaction %llu\n", trans->id);

    blk_status_t status = BLK_STS_OK;

    // IOERR if the number of bytes completed is less than the total
    if(trans->completed_bytes < trans->total_bytes) {
        status = BLK_STS_IOERR;
    }

    blk_update_request(trans->orig_rq, status, trans->completed_bytes);
    __blk_mq_end_request(trans->orig_rq, status);

    // Lock the transaction registry
    if (locking) spin_lock(&trans_tree_lock);

    // Move all chunks to a list
    for (node = rb_first(&(trans->chunk_tree)); node; node = rb_next(node)) {
        chk = rb_entry(node, chunk_t, node);
        list_add_tail(&chk->list, &chunk_list);
    }

    // Remove transaction from registry
    rb_erase(&trans->node, &trans_tree);

    // Unlock the transaction registry
    if (locking) spin_unlock(&trans_tree_lock);

    // Now, iterate over the list and release each chunk
    chunk_t *tmp;
    list_for_each_entry_safe(chk, tmp, &chunk_list, list) {
        list_del(&chk->list);
        remove_chunk(trans, chk);
    }

    // Free transaction
    vfree(trans);
}


void release_transaction(transaction_t *trans) {
    _release_transaction(trans, true);
}

int create_transaction_registry(void) {
    spin_lock_init(&trans_tree_lock);
    trans_tree = RB_ROOT;  // Reset the RB-tree root if necessary
    return 0;  // Return success status
}

int release_transaction_registry(void) {
    struct rb_node *node;
    transaction_t *trans;
    LIST_HEAD(trans_list);

    // First, lock the tree and move all transactions to a list
    spin_lock(&trans_tree_lock);

    for (node = rb_first(&trans_tree); node; node = rb_next(node)) {
        trans = rb_entry(node, transaction_t, node);
        list_add_tail(&trans->list, &trans_list);
        rb_erase(node, &trans_tree);
    }

    spin_unlock(&trans_tree_lock);

    // Now, iterate over the list and release each transaction
    transaction_t *tmp;
    list_for_each_entry_safe(trans, tmp, &trans_list, list) {
        list_del(&trans->list);
        _release_transaction(trans, false);
    }

    return 0;  // Return success status
}
