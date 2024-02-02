#include <linux/kthread.h>
#include <linux/mutex.h>

#include "udp_socket.h"
#include "packet.h"

#include "module.h"
#include "receive_thread.h"

// Externs
extern netdisk_config_t config;

// Thread pointer
static struct task_struct *receive_thread = NULL;

static DEFINE_MUTEX(rx_queue_mutex);
static DECLARE_WAIT_QUEUE_HEAD(data_available_wq);
static DECLARE_WAIT_QUEUE_HEAD(space_available_wq);
static struct list_head rx_queue;
static int rx_queue_size = 0;

static int run_receive_thread(void *data) {
    // Init rx_queue
    INIT_LIST_HEAD(&rx_queue);
    
    // Buffer
    packet_t *packet = NULL;
    wait_queue_head_t *socket_rx_wq = get_socket_wait_queue();
    
    printk(KERN_DEBUG "netdisk: receive_thread startup\n");

    while (!kthread_should_stop()) {
      // New packet
      if(!packet) packet = kmalloc(sizeof(packet_t), GFP_KERNEL);

      // Wait for and get a Packet
      wait_event_interruptible((*socket_rx_wq), !socket_receive_queue_empty());
      if (kthread_should_stop()) break;  // receive_thread was told to stop

      // Receive Packet
      int res = packet_recv(packet, config.key, false);
      if(res != NETDISK_PACKET_STATUS_OK) {
        printk(KERN_ALERT "netdisk: packet_recv failed (%d)\n", res);
        continue;
      }

      // Wait for space on the rx queue
      wait_event_interruptible(space_available_wq, rx_queue_size < 100);
      if (kthread_should_stop()) break;  // receive_thread was told to stop

      // Add it to the queue
      mutex_lock(&rx_queue_mutex);
      INIT_LIST_HEAD(&packet->rx_tx_list);
      list_add_tail(&(packet->rx_tx_list), &rx_queue);
      rx_queue_size++;
      mutex_unlock(&rx_queue_mutex);
      wake_up(&data_available_wq); // Notify space available

      packet = NULL;
    }

    // Free last unused packet buffer
    if(packet) kfree(packet);

    printk(KERN_DEBUG "netdisk: receive_thread shutdown\n");

    return 0;
}

int wait_for_packet(packet_t** packet) {
  wait_event_interruptible(data_available_wq, rx_queue_size > 0);

  mutex_lock(&rx_queue_mutex);
  if(rx_queue_size == 0) {
    mutex_unlock(&rx_queue_mutex);
    return -EINTR;;
  }

  *packet = list_first_entry(&rx_queue, packet_t, rx_tx_list);
  list_del(&(*packet)->rx_tx_list);
  INIT_LIST_HEAD(&(*packet)->rx_tx_list);
  rx_queue_size--;
  mutex_unlock(&rx_queue_mutex);
  wake_up(&space_available_wq);

  return 0;
}

// Create receive_thread
int receive_thread_start(void) {
  if(receive_thread != NULL) {
    printk(KERN_ALERT "netdisk: receive_thread_start called but thread already started\n");
    return 0;
  }

  printk(KERN_DEBUG "Starting receive thread\n");
    
    receive_thread = kthread_run(run_receive_thread, NULL, "run_receive_thread");
    if (IS_ERR(receive_thread)) {
        printk(KERN_INFO "netdisk: failed to create run_receive_thread\n");
        return PTR_ERR(receive_thread);
    }
  
  printk(KERN_DEBUG "Started receive thread\n");

  return 0;
}

void receive_thread_stop(void) {
  if(receive_thread == NULL) {
    printk(KERN_ALERT "netdisk: receive_thread_stop called but thread not started\n");
    return;
  }

  // Stop the receive_thread
  if (receive_thread) {
    printk(KERN_DEBUG "Stopping receive thread\n");
    kthread_stop(receive_thread);
    printk(KERN_DEBUG "Stopped receive thread\n");
    receive_thread = NULL;
  }
}

