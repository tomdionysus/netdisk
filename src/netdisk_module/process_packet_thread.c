#include "process_packet_thread.h"
#include "transaction.h"
#include "receive_thread.h"

// Thread pointer
static struct task_struct *process_packet_thread = NULL;

static void process_packet_start(packet_t *packet) {
  switch(packet->fields.reply) {
  case NETDISK_REPLY_OK:
    break;
  case NETDISK_REPLY_ERROR:
    break;
  default: 
    break;
  }
}

static void process_packet_stop(packet_t *packet) {
  switch(packet->fields.reply) {
  case NETDISK_REPLY_OK:
    break;
  case NETDISK_REPLY_ERROR:
    break;
  default: 
    break;
  }
}

static void process_packet_read(packet_t *packet) {
  switch(packet->fields.reply) {
  case NETDISK_REPLY_READ_OK:
    // Find transaction
    transaction_t *trans = find_transaction(packet->fields.user_data);
    if(trans == NULL) {
      printk(KERN_ALERT "netdisk: received unknown transaction from %pI4:%u\n", &packet->addr.sin_addr, ntohs(packet->addr.sin_port));
      break;
    }
    if(rq_data_dir(trans->orig_rq) != READ) {
      printk(KERN_ALERT "netdisk: NETDISK_REPLY_READ_OK received for non-READ transaction from %pI4:%u\n", &packet->addr.sin_addr, ntohs(packet->addr.sin_port));
      break;
    }
    // Find the chunk
    chunk_t *chk = find_chunk(trans, packet->fields.block_offset);
    if(chk == NULL) {
      printk(KERN_ALERT "netdisk: received unknown chunk from %pI4:%u\n", &packet->addr.sin_addr, ntohs(packet->addr.sin_port));
      break;
    }

    // Copy the data from packet
    memcpy(chk->data, packet->fields.payload, chk->size);

    chk->complete = true;
    printk(KERN_ALERT "netdisk: block READ completed block_id %llu (transaction %llu)\n", chk->block_id, trans->id);

    // Remove finished chunks
    remove_completed_chunks(trans);
    
    // If the transaction has completed, finish it
    if(list_empty(&trans->chunks)) {
      printk(KERN_ALERT "netdisk: transaction completed %llu/%llu chunks, %llu/%llu bytes (transaction %llu)\n", trans->completed_chunks, trans->total_chunks, trans->completed_bytes, trans->total_bytes, trans->id);
      release_transaction(trans);
    }
    break;
  case NETDISK_REPLY_OUT_OF_RANGE:
    break;
  case NETDISK_REPLY_ERROR:
    break;
  default: 
    break;
  }
}

static void process_packet_write(packet_t *packet) {
  switch(packet->fields.reply) {
  case NETDISK_REPLY_WRITE_OK:
    // Find transaction
    transaction_t *trans = find_transaction(packet->fields.user_data);
    if(trans == NULL) {
      printk(KERN_ALERT "netdisk: received unknown transaction from %pI4:%u\n", &packet->addr.sin_addr, ntohs(packet->addr.sin_port));
      break;
    }
    if(rq_data_dir(trans->orig_rq) != WRITE) {
      printk(KERN_ALERT "netdisk: NETDISK_REPLY_WRITE_OK received for non-WRITE transaction from %pI4:%u\n", &packet->addr.sin_addr, ntohs(packet->addr.sin_port));
      break;
    }

    // Find the chunk
    chunk_t *chk = find_chunk(trans, packet->fields.block_offset);
    if(chk == NULL) {
      printk(KERN_ALERT "netdisk: received unknown chunk from %pI4:%u\n", &packet->addr.sin_addr, ntohs(packet->addr.sin_port));
      break;
    }

    chk->complete = true;
    printk(KERN_ALERT "netdisk: block WRITE completed block_id %llu (transaction %llu)\n", chk->block_id, trans->id);

    // Remove finished chunks
    remove_completed_chunks(trans);

    // If the transaction has completed, finish it
    if(list_empty(&trans->chunks)) {
      printk(KERN_ALERT "netdisk: transaction completed %llu/%llu chunks, %llu/%llu bytes (transaction %llu)\n", trans->completed_chunks, trans->total_chunks, trans->completed_bytes, trans->total_bytes, trans->id);
      release_transaction(trans);
    }
    break;
  case NETDISK_REPLY_OUT_OF_RANGE:
    break;
  case NETDISK_REPLY_READ_ONLY:
    break;
  case NETDISK_REPLY_ERROR:
    break;
  default: 
    break;
  }
}

void process_packet(packet_t *packet) {
  printk(KERN_DEBUG "netdisk: received %s / %s from %pI4:%u\n", packet_command_to_str(packet->fields.command), packet_reply_to_str(packet->fields.reply), &packet->addr.sin_addr, ntohs(packet->addr.sin_port));

  switch(packet->fields.command) {
  case NETDISK_COMMAND_START:
    process_packet_start(packet);
    break;
    case NETDISK_COMMAND_STOP:
    process_packet_stop(packet);
    break;
    case NETDISK_COMMAND_READ:
    process_packet_read(packet);
    break;
    case NETDISK_COMMAND_WRITE:
    process_packet_write(packet);
    break;
  default:
    break;
  }
}

static int run_process_packet_thread(void *data) {
    // Buffer
    packet_t *packet;

    while (!kthread_should_stop()) {
      if(wait_for_packet(&packet) == 0) {
        process_packet(packet);
        kfree(packet);
      }
    }

    printk(KERN_DEBUG "netdisk: process_packet_thread shutdown\n");

    return 0;
}

// Create process_packet_thread
int process_packet_thread_start(void) {
  if(process_packet_thread != NULL) {
    printk(KERN_ALERT "netdisk: process_packet_thread_start called but thread already started\n");
    return 0;
  }

  printk(KERN_DEBUG "Starting process_packet thread\n");
    
    process_packet_thread = kthread_run(run_process_packet_thread, NULL, "run_process_packet_thread");
    if (IS_ERR(process_packet_thread)) {
        printk(KERN_INFO "netdisk: failed to create run_process_packet_thread\n");
        return PTR_ERR(process_packet_thread);
    }
  
  printk(KERN_DEBUG "Started process_packet thread\n");

  return 0;
}

void process_packet_thread_stop(void) {
  if(process_packet_thread == NULL) {
    printk(KERN_ALERT "netdisk: process_packet_thread_stop called but thread not started\n");
    return;
  }

  // Stop the process_packet_thread
  if (process_packet_thread) {
    printk(KERN_DEBUG "Stopping process_packet thread\n");
    kthread_stop(process_packet_thread);
    printk(KERN_DEBUG "Stopped process_packet thread\n");
    process_packet_thread = NULL;
  }
}
