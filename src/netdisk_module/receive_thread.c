#include <linux/kthread.h>

#include "udp_socket.h"
#include "packet.h"

#include "module.h"
#include "receive_thread.h"
#include "process_packet.h"

// Externs
extern netdisk_config_t config;

// Thread pointer
static struct task_struct *receive_thread = NULL;

static int run_receive_thread(void *data) {
    // Buffer
    packet_t *packet = kmalloc(sizeof(packet_t), GFP_KERNEL);
    printk(KERN_DEBUG "netdisk: receive_thread startup\n");
    struct sockaddr_in from_addr;

    DEFINE_WAIT(wait);
    wait_queue_head_t *sock_wait_queue = get_socket_wait_queue();

    while (!kthread_should_stop()) {
      prepare_to_wait(sock_wait_queue, &wait, TASK_INTERRUPTIBLE);

      if (kthread_should_stop()) {
          break;  // receive_thread was told to stop
      }
      if (socket_receive_queue_empty()) {
          schedule();  // No data, go to sleep
          continue;
      }
      finish_wait(sock_wait_queue, &wait);

      // Receive Packet
      if(packet_recv(packet, config.key, false, &from_addr)!= NETDISK_PACKET_STATUS_OK) {
        printk(KERN_ALERT "netdisk: packet_recv failed\n");
        continue;
      }
      process_packet(packet, &from_addr);
    }

    printk(KERN_ALERT "netdisk: receive_thread shutdown\n");
    kfree(packet);

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

