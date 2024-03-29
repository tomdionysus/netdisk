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
// Original by Oleg Kutkov (https://olegkutkov.me/2020/02/10/linux-block-device-driver)
// Adapted for linux-6.6.7-0-lts by Tom Cully 2023
//
// Tested under linux 6.6.7-0-lts
//
#include "module.h"

#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/types.h>
#include <linux/wait.h>

#include "netdisk_device.h"
#include "packet_kernel.h"
#include "receive_thread.h"
#include "send_thread.h"
#include "util.h"

// Parameters
static char *address = NULL;
static char *key = NULL;
static char *devicename = "netdisk";
static ushort port = NETDISK_DEFAULT_PORT;

// Config
netdisk_config_t config;

// Session
session_t *session;

// Parameters
module_param(address, charp, 0000);
MODULE_PARM_DESC(address, "IPv4 address of the netdisk server");

module_param(port, ushort, 0000);
MODULE_PARM_DESC(port, "Port number");

module_param(key, charp, 0000);
MODULE_PARM_DESC(key, "64 character, 32 byte hex value");

module_param(devicename, charp, 0000);
MODULE_PARM_DESC(devicename, "Device name");

int load_parameters(void) {
  if (!address || in4_pton(address, -1, (u8 *)&(config.address.sin_addr), '\0', NULL) == 0) {
    printk(KERN_ERR "netdisk: address must be a valid IP address\n");
    return -EINVAL;
  }

  config.address.sin_family = AF_INET;
  config.address.sin_port = htons(port);

  if (!key || strlen(key) != 64 || parse_key(key, config.key) == -EINVAL) {
    printk(KERN_ERR "netdisk: key must be a 64 character hex value\n");
    return -EINVAL;
  }

  config.devicename = devicename;
  return 0;
}

static int __init netdisk_driver_init(void) {
  // Validate parameters
  if (load_parameters() == -EINVAL) {
    return -EINVAL;
  }

  // Setup session
  session = kmalloc(sizeof(session_t), GFP_KERNEL);
  memset(session, 0, sizeof(session_t));
  session->state = NETDISK_SESSION_STATE_INITIAL;

  // Setup AES
  if ((session->aes_context = AES_CBC_alloc(config.key)) == NULL) {
    printk(KERN_ERR "netdisk: cannot create AES CBC context");
    kfree(session);
    return -EINVAL;
  }

  // Create Socket
  if (packet_create_client_socket(&session->socket_fd, &config.address) != 0) {
    printk(KERN_ERR "netdisk: cannot connect to server: %pI4 port: %hu\n", &config.address.sin_addr, ntohs(config.address.sin_port));
    AES_CBC_release(session->aes_context);
    kfree(session);
    return -EINVAL;
  }

  // Receive Thread
  receive_thread_start(session);

  // Send Thread
  send_thread_start(session);

  // Start Device
  create_netdisk_device(config.devicename, session->socket_fd);

  // Loaded Banner
  printk(KERN_NOTICE "netdisk: loaded. Server: %pI4 Port: %hu, Device Name: %s\n", &config.address.sin_addr, ntohs(config.address.sin_port), config.devicename);

  return 0;
}

static void __exit netdisk_driver_exit(void) {
  // Release device
  release_netdisk_device();

  // Send Thread
  send_thread_stop(session);

  // Receive Thread
  receive_thread_stop(session);

  // Kill all transactions
  release_all_transactions();

  // Release socket
  packet_destroy_socket(session->socket_fd);

  // Release AES
  AES_CBC_release(session->aes_context);

  // Free the session
  kfree(session);
}

module_init(netdisk_driver_init);
module_exit(netdisk_driver_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tom Cully");
MODULE_DESCRIPTION("The netdisk kernel driver module");
