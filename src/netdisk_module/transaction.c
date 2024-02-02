#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/list.h>
#include <linux/list.h>
#include <linux/slab.h>

#include "transaction.h"
#include "packet.h"
#include "send_thread.h"

static struct rb_root trans_tree = RB_ROOT;
DEFINE_MUTEX(transaction_tree_mutex);

// Function to process and release timed out transactions
void release_timed_out_transactions(void) {
    struct rb_node *node;
    transaction_t *trans, *tmp;
    LIST_HEAD(timed_out_transactions);

    int count = 0;
    int timedout = 0;

    mutex_lock(&transaction_tree_mutex);
    // First pass: iterate over the tree and collect transactions that have timed out
    for (node = rb_first(&trans_tree); node; node = rb_next(node)) {
        trans = rb_entry(node, transaction_t, node);
        count++;
        ktime_t now = ktime_get();
        if (ktime_compare(now, trans->timeout) >= 0) {
            INIT_LIST_HEAD(&trans->remove_list);
            list_add_tail(&trans->remove_list, &timed_out_transactions);
            timedout++;
        }
    }
    mutex_unlock(&transaction_tree_mutex);

    // Second pass: process and release collected transactions
    list_for_each_entry_safe(trans, tmp, &timed_out_transactions, remove_list) {
        list_del(&trans->remove_list);
        INIT_LIST_HEAD(&trans->remove_list);
        printk(KERN_ALERT "netdisk: transaction timed out %llu/%llu chunks, %llu/%llu bytes (transaction %llu)\n", trans->completed_chunks, trans->total_chunks, trans->completed_bytes, trans->total_bytes, trans->id);
        release_transaction(trans);
    }

}

transaction_t *create_transaction(u64 id, struct request *rq) {

    printk(KERN_ALERT "netdisk: creating new transaction %llu direction %s\n", id, rq_data_dir(rq) == WRITE ? "WRITE" : "READ");

    transaction_t *trans = kzalloc(sizeof(transaction_t), GFP_KERNEL);
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

    // Set the timeout to 10 seconds from now
    trans->timeout = ktime_add(ktime_get(), ktime_set(10, 0));

    // Used in timeout or exit
    INIT_LIST_HEAD(&trans->remove_list);

    // Protects chunks
    INIT_LIST_HEAD(&trans->chunks);
    mutex_init(&trans->chunk_mutex);

    if (insert_transaction(trans) != 0) {
        kfree(trans);
        return NULL;
    }

    return trans;
}

int insert_transaction(transaction_t *trans) {
    struct rb_node **new = &(trans_tree.rb_node), *parent = NULL;
    
    // Lock the transaction registry
    mutex_lock(&transaction_tree_mutex);

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
            mutex_unlock(&transaction_tree_mutex);
            printk(KERN_ALERT "netdisk: !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! duplicate transaction id %llu\n", trans->id);
            return -EEXIST;
        }
    }

    // Add the new node to the RB-tree
    rb_link_node(&trans->node, parent, new);
    rb_insert_color(&trans->node, &trans_tree);

    // Unlock the transaction registry
    mutex_unlock(&transaction_tree_mutex);
    return 0;
}

chunk_t* create_chunk(transaction_t *trans, u64 block_id, void *data, size_t size) {
    chunk_t *chk = kzalloc(sizeof(chunk_t), GFP_KERNEL);
    if (!chk) return NULL;

    chk->block_id = block_id;
    chk->data = data;
    chk->size = size;
    chk->complete = false;
    chk->timeout = ktime_add(ktime_get(), ktime_set(1, 0));

    if (insert_chunk(trans, chk) != 0) {
        kfree(chk);
        return NULL;
    }

    return chk;
}

int insert_chunk(transaction_t *trans, chunk_t *chk) {
    struct rb_node **new = &(trans->chunk_tree.rb_node), *parent = NULL;

    // Lock the transaction chunk tree
    mutex_lock(&trans->chunk_mutex);

    // Figure out where to put the new node
    while (*new) {
        chunk_t *this = container_of(*new, chunk_t, node);
        parent = *new;
        if (chk->block_id < this->block_id) {
            new = &((*new)->rb_left);
        } else if (chk->block_id > this->block_id) {
            new = &((*new)->rb_right);
        } else {
            mutex_unlock(&trans->chunk_mutex);
            printk(KERN_ALERT "netdisk: !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! duplicate chunk id %llu\n", chk->block_id);
            return -EEXIST;
        }
    }

    // Add the new node to the RB-tree
    RB_CLEAR_NODE(&chk->node);
    rb_link_node(&chk->node, parent, new);
    rb_insert_color(&chk->node, &(trans->chunk_tree));

    // Add the new node in the chunk list
    INIT_LIST_HEAD(&chk->chunk_list);
    list_add_tail(&chk->chunk_list, &(trans->chunks));

    // Unlock the transaction chunk tree
    mutex_unlock(&trans->chunk_mutex);
    return 0;
}

chunk_t *find_chunk(transaction_t *trans, u64 block_id) {
    struct rb_node *node = trans->chunk_tree.rb_node;

    // Lock the transaction chunk tree
    mutex_lock(&trans->chunk_mutex);

    while (node) {
        chunk_t *chk = container_of(node, chunk_t, node);
        if (block_id < chk->block_id) {
            node = node->rb_left;
        } else if (block_id > chk->block_id) {
            node = node->rb_right;
        } else {
            mutex_unlock(&trans->chunk_mutex);
            return chk; // Found it
        }
    }

    mutex_unlock(&trans->chunk_mutex);
    return NULL;
}

transaction_t *find_transaction(u64 id) {
    struct rb_node *node = trans_tree.rb_node;

    // Lock the transaction registry
    mutex_lock(&transaction_tree_mutex);

    while (node) {
        transaction_t *trans = container_of(node, transaction_t, node);
        if (id < trans->id) {
            node = node->rb_left;
        } else if (id > trans->id) {
            node = node->rb_right;
        } else {
            // Unlock the transaction registry
            mutex_unlock(&transaction_tree_mutex);
            return trans; // Found it
        }
    }

    // Unlock the transaction registry
    mutex_unlock(&transaction_tree_mutex);
    return NULL;
}

void remove_completed_chunks(transaction_t *trans) {
    // Now, iterate over the list
    // * blk_update_request completed chunks and remove then
    // * Rerequest timed out chunks
    chunk_t *chk;
    chunk_t *tmp;
    bool sofar = true;
    list_for_each_entry_safe(chk, tmp, &trans->chunks, chunk_list) {
        if(sofar && chk->complete) {
            // Lock the transaction chunk tree
            mutex_lock(&trans->chunk_mutex);
            // Remove from transaction chunk list
            list_del(&chk->chunk_list);
            INIT_LIST_HEAD(&chk->chunk_list);
            rb_erase(&chk->node, &trans->chunk_tree);

            trans->completed_chunks++;
            trans->completed_bytes += chk->size;

            // Unlock the transaction chunk tree
            mutex_unlock(&trans->chunk_mutex);

            // Free chunk
            kfree(chk);

            // Report completed to request
            blk_update_request(trans->orig_rq, BLK_STS_OK, trans->completed_bytes);
        } else {
            // We don't have a continuous block state.
            sofar = false;

            // Check timeout
            ktime_t now = ktime_get();
            if (ktime_compare(now, chk->timeout) >= 0 && chk->retries>3) {
                // Let the transaction time out
            } else {
                // Reset timeout, increment retries
                chk->timeout = ktime_get();
                chk->retries++; 

                printk(KERN_ALERT "netdisk: re-request for block %llu (transaction %llu)\n", chk->block_id, trans->id);

                // Rerequest block
                send_chunk_request(trans, chk);
            }
        }
    }
}

void release_transaction(transaction_t *trans) {
    struct rb_node *node;
    chunk_t *chk;
    LIST_HEAD(release_chunk_list);

    printk(KERN_ALERT "netdisk: notifying blk_update_request for transaction %llu\n", trans->id);

    blk_status_t status = BLK_STS_OK;

    // IOERR if the number of chunks completed is less than the total
    if(trans->completed_chunks < trans->total_chunks) {
        status = BLK_STS_IOERR;
    }

    blk_update_request(trans->orig_rq, status, trans->completed_bytes);
    blk_mq_end_request(trans->orig_rq, status);

    // Move all chunks to a list
    for (node = rb_first(&(trans->chunk_tree)); node; node = rb_next(node)) {
        chk = rb_entry(node, chunk_t, node);
        list_add_tail(&chk->chunk_list, &release_chunk_list);
    }

    // All these chunks are dead, just free them
    chunk_t *tmp;
    list_for_each_entry_safe(chk, tmp, &release_chunk_list, chunk_list) {
        list_del(&chk->chunk_list);
        rb_erase(&chk->node, &trans->chunk_tree);
        INIT_LIST_HEAD(&chk->chunk_list);
        kfree(chk);
    }

    // Remove transaction from registry
    mutex_lock(&transaction_tree_mutex);
    rb_erase(&trans->node, &trans_tree);
    mutex_unlock(&transaction_tree_mutex);

    // Free transaction
    kfree(trans);
}

int create_transaction_registry(void) {
    trans_tree = RB_ROOT;  // Reset the RB-tree root if necessary
    return 0;  // Return success status
}

int release_transaction_registry(void) {
    struct rb_node *node;
    transaction_t *trans;
    LIST_HEAD(trans_list);

    // First, lock the tree and move all transactions to a list
    mutex_lock(&transaction_tree_mutex);

    for (node = rb_first(&trans_tree); node; node = rb_next(node)) {
        trans = rb_entry(node, transaction_t, node);
        INIT_LIST_HEAD(&trans->remove_list);
        list_add_tail(&trans->remove_list, &trans_list);
    }

    mutex_unlock(&transaction_tree_mutex);

    // Now, iterate over the list and release each transaction
    transaction_t *tmp;
    list_for_each_entry_safe(trans, tmp, &trans_list, remove_list) {
        list_del(&trans->remove_list);
        INIT_LIST_HEAD(&trans->remove_list);
        release_transaction(trans);
    }

    return 0;  // Return success status
}
