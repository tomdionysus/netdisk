#include <linux/kthread.h>
#include <linux/mutex.h>

#include "udp_socket.h"
#include "packet.h"

#include "module.h"
#include "send_thread.h"

// Externs
extern netdisk_config_t config;

// Thread pointer
static struct task_struct *send_thread = NULL;

static DEFINE_MUTEX(tx_queue_mutex);
static DECLARE_WAIT_QUEUE_HEAD(data_available_wq);
static DECLARE_WAIT_QUEUE_HEAD(space_available_wq);
static struct list_head tx_queue;
static int tx_queue_size = 0;

static int run_send_thread(void *data) {
    // Init tx_queue
    INIT_LIST_HEAD(&tx_queue);
    
    // Buffer
    packet_t *packet = NULL;

    printk(KERN_DEBUG "netdisk: send_thread startup\n");

    while (!kthread_should_stop()) {
      // Wait for a packet to send
      wait_event_interruptible(data_available_wq, tx_queue_size > 0); 
      if (kthread_should_stop()) break;  // send_thread was told to stop

      mutex_lock(&tx_queue_mutex);
      if(tx_queue_size == 0) {
        mutex_unlock(&tx_queue_mutex);
        continue;
      }

      // New packet
      packet = list_first_entry(&tx_queue, packet_t, rx_tx_list);
      list_del(&(packet->rx_tx_list));
      INIT_LIST_HEAD(&packet->rx_tx_list);
      tx_queue_size--;
      mutex_unlock(&tx_queue_mutex);
      
      wake_up(&space_available_wq);

      // Send Packet
      int res = packet_send(packet, config.key);
      if(res != NETDISK_PACKET_STATUS_OK) {
        printk(KERN_ALERT "netdisk: packet_send failed (%d)\n", res);
      }

      kfree(packet);
    }

    // Free last unused packet buffer
    if(packet) kfree(packet);

    printk(KERN_DEBUG "netdisk: send_thread shutdown\n");

    return 0;
}

int send_packet_enqueue(packet_t* packet) {
  wait_event_interruptible(space_available_wq, tx_queue_size < 100);

  mutex_lock(&tx_queue_mutex);
  if(tx_queue_size >= 100) {
    mutex_unlock(&tx_queue_mutex);
    return -EINTR;
  }

  // Add it to the queue
  INIT_LIST_HEAD(&packet->rx_tx_list);
  list_add_tail(&packet->rx_tx_list, &tx_queue);
  tx_queue_size++;
  mutex_unlock(&tx_queue_mutex);
  
  wake_up(&data_available_wq); // Notify space available

  return 0;
}

int send_chunk_request(transaction_t *trans, chunk_t *chk) {
  printk(KERN_DEBUG "netdisk: send_chunk_request (transaction %llu, block_id %llu)", trans->id, chk->block_id);

    // Make a packet
    packet_t *packet = kmalloc(sizeof(packet_t), GFP_KERNEL);
    packet_init(packet);

    // Fill in transaction id, block offset
    packet->fields.block_offset = chk->block_id;
    packet->fields.user_data = trans->id;
    packet->addr = config.address;

    if(rq_data_dir(trans->orig_rq) == WRITE) {
        packet->fields.command = NETDISK_COMMAND_WRITE;
        memcpy(packet->fields.payload, chk->data, chk->size);
    } else {
        packet->fields.command = NETDISK_COMMAND_READ;
    }
    return send_packet_enqueue(packet);
}


// Create send_thread
int send_thread_start(void) {
  if(send_thread != NULL) {
    printk(KERN_ALERT "netdisk: send_thread_start called but thread already started\n");
    return 0;
  }

  printk(KERN_DEBUG "Starting send thread\n");
    
    send_thread = kthread_run(run_send_thread, NULL, "run_send_thread");
    if (IS_ERR(send_thread)) {
        printk(KERN_INFO "netdisk: failed to create run_send_thread\n");
        return PTR_ERR(send_thread);
    }
  
  printk(KERN_DEBUG "Started send thread\n");

  return 0;
}

void send_thread_stop(void) {
  if(send_thread == NULL) {
    printk(KERN_ALERT "netdisk: send_thread_stop called but thread not started\n");
    return;
  }

  // Stop the send_thread
  if (send_thread) {
    printk(KERN_DEBUG "Stopping send thread\n");
    kthread_stop(send_thread);
    printk(KERN_DEBUG "Stopped send thread\n");
    send_thread = NULL;
  }
}

