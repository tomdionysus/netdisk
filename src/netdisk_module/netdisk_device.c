#include "netdisk_device.h"

#include "module.h"
#include "packet.h"
#include "send_thread.h"
#include "transaction.h"

static int dev_major = 0;
static struct netdisk *dev = NULL;

extern netdisk_config_t config;
extern struct rb_root trans_tree;

static int netdisk_open(struct gendisk *disk, blk_mode_t mode) {
  if (!blk_get_queue(disk->queue)) {
    printk(KERN_ERR "netdisk: blk_get_queue cannot get queue");
    return -ENXIO;
  }

  printk(KERN_INFO "netdisk: netdisk_open");

  return 0;
}

static void netdisk_release(struct gendisk *disk) {
  blk_put_queue(disk->queue);

  printk(KERN_INFO "netdisk: netdisk_release");
}

static int netdisk_ioctl(struct block_device *bdev, fmode_t mode, unsigned cmd, unsigned long arg) {
  if (cmd == HDIO_GETGEO) {
    printk(KERN_NOTICE "netdisk: netdisk_ioctl::HDIO_GETGEO");

    struct hd_geometry geo;
    geo.heads = 4;
    geo.sectors = 16;
    geo.cylinders = (dev->capacity_sectors & ~0x3f) >> 6;
    geo.start = 4;
    if (copy_to_user((void *)arg, &geo, sizeof(geo))) {
      printk(KERN_ERR "netdisk: copy_to_user failed during HDIO_GETGEO");
      return -EFAULT;
    }
    return 0;
  }

  return -ENOTTY;
}

static int netdisk_process_request(struct request *rq) {
    int ret = 0;
    struct bio_vec bvec;
    struct req_iterator iter;
    uint32_t block_id = blk_rq_pos(rq);

    // Transaction
    u64 transaction_id = get_random_u64();
    transaction_t *trans = create_transaction(transaction_id, rq);
    if (!trans) return -ENOMEM;

    // Iterate over all requests segments
    rq_for_each_segment(bvec, rq, iter)
    {
        // Get data buffer and size
        void* b_buf = page_address(bvec.bv_page) + bvec.bv_offset;

        // Create the chunk
        chunk_t *chk = create_chunk(trans, block_id, b_buf, bvec.bv_len);
        if (!chk) {
          printk(KERN_ALERT "netdisk: create_chunk failed (transaction %llu, block_id %u)", trans->id, block_id);
          return BLK_STS_IOERR;
        }

        // printk(KERN_INFO "netdisk: create_chunk transaction %llu, block_id %u, length %u (%u blocks)", trans->id, block_id, bvec.bv_len, bvec.bv_len >> 9);

        enqueue_chunk(trans, chk);

        // Increment block_id
        block_id += bvec.bv_len >> 9;
    }

    return ret;
}

void netdisk_complete_chunk(session_t *session, packet_header_t *header) {
  transaction_t *trans;
  if ((trans = find_transaction(header->transaction_id)) == NULL) {
    return;
  }

  chunk_t *chunk;
  if ((chunk = find_chunk(trans, header->block_id)) == NULL) {
    printk(KERN_ERR "netdisk: chunk %llu not found (transaction %llu)", header->block_id, header->transaction_id);
    return;
  }

  // If there's data, receive and decrypt.
  if (rq_data_dir(trans->request) == READ && header->length > 0) {
    if (packet_recv(session->socket_fd, chunk->buffer, header->length, 10000) != header->length) {
      printk(KERN_ALERT "netdisk: receive packet data timeout (%d bytes)", header->length);
      return;
    }
    // And Decrypt it
    AES_CBC_decrypt_buffer(&session->rx_aes_context, chunk->buffer, header->length);

    if(chunk->size != header->length) {
      printk(KERN_ERR "netdisk: packet size mismatch %u != %u (transaction %llu, chunk %llu)", chunk->size, header->length, header->transaction_id, header->block_id);
    }
  }

  // printk(KERN_NOTICE "netdisk: chunk %llu complete (transaction %llu, block %d of %d)", block_id, trans_id, trans->completed_chunks, trans->total_chunks);

  // Release the chunk
  release_chunk(trans, header->block_id);

  // Report completed to request
  blk_update_request(trans->request, BLK_STS_OK, trans->completed_bytes);

  // If all the chunks are complete
  if (trans->completed_chunks == trans->total_chunks) {
    // printk(KERN_NOTICE "netdisk: transaction %llu complete", trans_id);

    // End the request
    blk_mq_end_request(trans->request, BLK_STS_OK);

    // Release the transaction
    release_transaction(header->transaction_id);
  }
}

void netdisk_error_chunk(u64 trans_id, u64 block_id, u8 error) {
  transaction_t *trans;
  if ((trans = find_transaction(trans_id)) == NULL) {
    return;
  }

  chunk_t *chunk;
  if ((chunk = find_chunk(trans, block_id)) == NULL) {
    printk(KERN_ALERT "netdisk: chunk %llu not found (transaction %llu)", block_id, trans_id);
    return;
  }

  // Release the chunk
  release_chunk(trans, block_id);

  // End the request with error
  blk_update_request(trans->request, BLK_STS_IOERR, trans->completed_bytes);
  blk_mq_end_request(trans->request, BLK_STS_IOERR);

  // Release the transaction
  release_transaction(trans_id);
}

// queue callback function
static blk_status_t netdisk_queue_request(struct blk_mq_hw_ctx *hctx, const struct blk_mq_queue_data *bd) {
  blk_status_t status = BLK_STS_OK;
  struct request *rq = bd->rq;

  // Start request serving procedure
  blk_mq_start_request(rq);

  if (netdisk_process_request(rq) != 0) {
    status = BLK_STS_IOERR;
  }

  return status;
}

static struct block_device_operations netdisk_ops = {
    .owner = THIS_MODULE,
    .open = netdisk_open,
    .release = netdisk_release,
    .ioctl = netdisk_ioctl,
};

static struct blk_mq_ops netdisk_mq_ops = {
    .queue_rq = netdisk_queue_request,
};

int create_netdisk_device(char *devicename, struct socket *tcp_socket) {
  // Register new block device and get device major number
  dev_major = register_blkdev(dev_major, devicename);
  if (dev_major < 0) {
    printk(KERN_ERR "netdisk: register block device failed\n");
    return -EBUSY;
  }

  // Allocate the block device structure
  dev = kzalloc(sizeof(struct netdisk), GFP_KERNEL);
  dev->_disk_added = false;
  dev->tcp_socket = tcp_socket;

  if (dev == NULL) {
    printk(KERN_ERR "netdisk: failed to allocate devicev\n");
    release_netdisk_device();

    return -ENOMEM;
  }

  // Allocate the actual netdisk from virtual memory
  dev->capacity_sectors = (TOTAL_SECTORS * SECTOR_SIZE) >> SECTOR_SHIFT;

  // Allocate new disk
  dev->disk = blk_alloc_disk(1);
  if (dev->disk == NULL) {
    printk(KERN_ERR "netdisk: blk_alloc_disk failed");
    release_netdisk_device();

    return -ENOMEM;
  }

  // Initialise and Configure the tag set for queue
  dev->tag_set = kzalloc(sizeof(struct blk_mq_tag_set), GFP_KERNEL);
  if (dev->tag_set == NULL) {
    printk(KERN_ERR "netdisk: failed to allocate blk_mq_tag_set\n");
    release_netdisk_device();

    return -ENOMEM;
  }

  dev->tag_set->ops = &netdisk_mq_ops;
  dev->tag_set->queue_depth = 128;
  dev->tag_set->numa_node = NUMA_NO_NODE;
  dev->tag_set->flags = BLK_MQ_F_SHOULD_MERGE;
  dev->tag_set->nr_hw_queues = 1;
  dev->tag_set->cmd_size = 0;

  // Set it up in the system
  int err = blk_mq_alloc_tag_set(dev->tag_set);
  if (err) {
    printk(KERN_ERR "netdisk: blk_mq_alloc_tag_set returned error %d\n", err);
    release_netdisk_device();

    return -ENOMEM;
  }

  // Allocate queues
  if (blk_mq_init_allocated_queue(dev->tag_set, dev->disk->queue)) {
    printk(KERN_ERR "netdisk: blk_mq_init_allocated_queue failed");
    release_netdisk_device();

    return -ENOMEM;
  }
  blk_queue_rq_timeout(dev->disk->queue, BLK_DEFAULT_SG_TIMEOUT);
  dev->disk->queue->queuedata = dev;

  // Set all required flags and data
  dev->disk->flags = GENHD_FL_NO_PART;
  dev->disk->major = dev_major;
  dev->disk->first_minor = 0;
  dev->disk->minors = 1;
  dev->disk->fops = &netdisk_ops;
  dev->disk->private_data = dev;

  // Set device name as it will be represented in /dev
  sprintf(dev->disk->disk_name, devicename);

  // Set device capacity_sectors
  set_capacity(dev->disk, dev->capacity_sectors);

  // Set the logical block size
  blk_queue_logical_block_size(dev->disk->queue, SECTOR_SIZE);

  // Notify kernel about new disk device
  err = device_add_disk(NULL, dev->disk, NULL);
  if (err) {
    printk(KERN_ERR "netdisk: device_add_disk returned error %d\n", err);
    release_netdisk_device();

    return -ENOMEM;
  }

  // Mark add_disk succeeded
  dev->_disk_added = true;

  return 0;
}

void error_all_transactions(void) {
  // Iterate all transactions and report IOERR

  struct rb_node *next, *node = rb_first(&trans_tree);
  while (node) {
    transaction_t *trans = container_of(node, transaction_t, node);
    next = rb_next(node);

    // End the request with error
    blk_mq_end_request(trans->request, BLK_STS_IOERR);

    node = next;
  }
}

int release_netdisk_device(void) {
  if (dev) {
    if (dev->_disk_added) {
      // Remove the block device
      del_gendisk(dev->disk);
      // Free the block device
      put_disk(dev->disk);
      // For belt and braces if there's a failure later on
      dev->_disk_added = false;
    }

    if (dev->tag_set) {
      blk_mq_free_tag_set(dev->tag_set);
      kfree(dev->tag_set);
    }

    kfree(dev);
    dev = NULL;
  }

  if (dev_major > 0) {
    unregister_blkdev(dev_major, "netdisk");
  }

  return 0;
}
