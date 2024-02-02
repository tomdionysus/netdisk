#include "module.h"

#include "netdisk_device.h"
#include "packet.h"
#include "send_thread.h"

static int dev_major = 0;
static struct netdisk *dev = NULL;

extern netdisk_config_t config;

static int netdisk_open(struct gendisk *disk, blk_mode_t mode)
{
    if(!blk_get_queue(disk->queue)){ 
        printk(KERN_ERR "netdisk: blk_get_queue cannot get queue");
        return -ENXIO;
    }

    printk(KERN_INFO "netdisk: netdisk_open");

    return 0;
}

static void netdisk_release(struct gendisk *disk)
{
    blk_put_queue(disk->queue);

    printk(KERN_INFO "netdisk: netdisk_release");
}

static int netdisk_ioctl(struct block_device *bdev, fmode_t mode, unsigned cmd, unsigned long arg)
{
    if(cmd == HDIO_GETGEO) {
        printk(KERN_DEBUG "netdisk: netdisk_ioctl::HDIO_GETGEO");

        struct hd_geometry geo;
        geo.heads = 4;
        geo.sectors = 16;
        geo.cylinders = (dev->capacity_sectors & ~0x3f) >> 6;
        geo.start = 4;
        if (copy_to_user((void*)arg, &geo, sizeof(geo))) {
            printk(KERN_ERR "netdisk: copy_to_user failed during HDIO_GETGEO");
            return -EFAULT;
        }
        return 0;
    }

    return -ENOTTY;
}

// Serve requests
static int netdisk_process_request(struct request *rq) {
    struct bio_vec bvec;
    struct req_iterator iter;
    loff_t pos = blk_rq_pos(rq) << SECTOR_SHIFT;
    u64 transaction_id = get_random_u64();
    transaction_t *trans = create_transaction(transaction_id, rq);
    if (!trans)
        return -ENOMEM;

    trans->total_chunks = 0;

    rq_for_each_segment(bvec, rq, iter) {
      unsigned long b_len = bvec.bv_len;
      void *b_buf = page_address(bvec.bv_page) + bvec.bv_offset;
      u64 block_id = pos >> SECTOR_SHIFT;

      while (b_len) {
        size_t chunk_size = min(b_len, (unsigned long)SECTOR_SIZE);
        
        chunk_t* chk = create_chunk(trans, block_id, b_buf, chunk_size);
        if (!chk) {
            printk(KERN_ERR "netdisk: create_chunk failed (transaction %llu, block_id %llu)", trans->id, block_id);
            return BLK_STS_IOERR;
        }

        trans->total_chunks++;

        pos += chunk_size;
        b_buf += chunk_size;
        b_len -= chunk_size;
        block_id++;

        trans->total_bytes += chunk_size;

        send_chunk_request(trans, chk);
      }
    }

    trans->completed_bytes = 0;

    return 0;
}

// queue callback function
static blk_status_t netdisk_queue_request(struct blk_mq_hw_ctx *hctx, const struct blk_mq_queue_data* bd)
{
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

int create_netdisk_device(char *devicename) {
      // Register new block device and get device major number
    dev_major = register_blkdev(dev_major, devicename);
    if (dev_major < 0) {
        printk(KERN_ERR "netdisk: register_blkdev failed\n");
        return -EBUSY;
    }

    // Allocate the block device structure
    dev = kzalloc(sizeof(struct netdisk), GFP_KERNEL);
    dev->_disk_added = false;

    if (dev == NULL) {
        printk(KERN_ERR "netdisk: Failed to allocate struct dev\n");
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
        printk(KERN_ERR "netdisk: Failed to allocate blk_mq_tag_set\n");
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

int release_netdisk_device(void) {
    if(dev) {
        if(dev->_disk_added) {
            // Remove the block device
            del_gendisk(dev->disk);
            // Free the block device 
            put_disk(dev->disk);
            // For belt and braces if there's a failure later on
            dev->_disk_added = false;
        }

        if(dev->tag_set) {
            blk_mq_free_tag_set(dev->tag_set);
            kfree(dev->tag_set);
        }

        kfree(dev);
        dev = NULL;
    }


    if(dev_major>0) {
        unregister_blkdev(dev_major, "netdisk");
    }

    return 0;
}
