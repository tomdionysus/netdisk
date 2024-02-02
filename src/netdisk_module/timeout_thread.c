#include <linux/kthread.h>

#include "udp_socket.h"
#include "packet.h"

#include "module.h"
#include "timeout_thread.h"
#include "transaction.h"

// Global Config
extern netdisk_config_t config;

// Thread pointer
static struct task_struct *timeout_thread = NULL;

static int run_timeout_thread(void *data) {
    printk(KERN_DEBUG "netdisk: timeout_thread startup\n");

    while (!kthread_should_stop()) {
        release_timed_out_transactions();

        // Set the current task state to interruptible sleep
        set_current_state(TASK_INTERRUPTIBLE);

        // Schedule a timeout for 1 second (HZ is the number of timer ticks per second)
        schedule_timeout(HZ*5);

        // After waking up, set the task state back to running
        set_current_state(TASK_RUNNING);
    }

    printk(KERN_ALERT "netdisk: timeout_thread shutdown\n");

    return 0;
}

// Create timeout_thread
int timeout_thread_start(void) {
    if(timeout_thread != NULL) {
        printk(KERN_ALERT "netdisk: timeout_thread_start called but thread already started\n");
        return 0;
    }

    printk(KERN_DEBUG "Starting timeout thread\n");
    
    timeout_thread = kthread_run(run_timeout_thread, NULL, "run_timeout_thread");
    if (IS_ERR(timeout_thread)) {
        printk(KERN_INFO "netdisk: failed to create run_timeout_thread\n");
        return PTR_ERR(timeout_thread);
    }
    
    printk(KERN_DEBUG "Started timeout thread\n");

  return 0;
}

void timeout_thread_stop(void) {
    if(timeout_thread == NULL) {
        printk(KERN_ALERT "netdisk: timeout_thread_stop called but thread not started\n");
        return;
    }

  // Stop the timeout_thread
  if (timeout_thread) {
    printk(KERN_DEBUG "Stopping timeout thread\n");
    kthread_stop(timeout_thread);
    printk(KERN_DEBUG "Stopped timeout thread\n");
    timeout_thread = NULL;
  }
}


