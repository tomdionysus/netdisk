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
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/types.h>

#include "module.h"
#include "packet.h"
#include "udp_socket.h"
#include "netdisk_device.h"
#include "transaction.h"
#include "receive_thread.h"
#include "send_thread.h"
#include "timeout_thread.h"
#include "process_packet_thread.h"
#include "util.h"

// Parameters
static char *address = NULL;
static char *key = NULL;
static char *devicename = "netdisk";
static ushort port = NETDISK_DEFAULT_PORT;

// Config
netdisk_config_t config;

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
        printk(KERN_ALERT "netdisk: address must be a valid IP address\n");
        return -EINVAL;
    }

    config.address.sin_family = AF_INET;
    config.address.sin_port = htons(port);

    if (!key || strlen(key) != 64 || parse_key(key, config.key) == -EINVAL) {
        printk(KERN_ALERT "netdisk: key must be a 64 character hex value\n");
        return -EINVAL;
    }

    config.devicename = devicename;
    return 0;
}

static int __init netdisk_driver_init(void)
{
    // Validate parameters
    if(load_parameters() == -EINVAL) {
        return -EINVAL;
    }

    // Create transaction registry
    create_transaction_registry();

    // Create UDP Socket
    if(create_udp_socket()!=0) {
        return -EINVAL;
    }

    // TX/RX Start
    receive_thread_start();
    send_thread_start();

    // Create timeout thread
    timeout_thread_start();

    // Send NETDISK_COMMAND_START
    packet_t *packet = kmalloc(sizeof(packet_t), GFP_KERNEL);
    packet_init(packet);
    packet->fields.command = NETDISK_COMMAND_START;
    packet->addr = config.address;
    send_packet_enqueue(packet);

    // Start Device
    create_netdisk_device(config.devicename);

    // Start packet processor
    process_packet_thread_start();

    // Loaded Banner
    char displaykey[65];
    buffer_to_hex_string(config.key, 32, displaykey, 65);
    printk(KERN_DEBUG "netdisk: Module loaded. Server: %pI4 Port: %hu, Key: %s, Device Name: %s\n", &config.address.sin_addr, ntohs(config.address.sin_port), displaykey, config.devicename);

    return 0;
}

static void __exit netdisk_driver_exit(void)
{
    // Stop packet processor
    process_packet_thread_stop();

    // TX/RX Stop
    send_thread_stop();
    receive_thread_stop();

    // Timeout thread stop
    timeout_thread_stop();

    // Release device
    release_netdisk_device();

    // Release UDP socket
    release_udp_socket();

    // Release the transaction registry
    release_transaction_registry();
}

module_init(netdisk_driver_init);
module_exit(netdisk_driver_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tom Cully");
MODULE_DESCRIPTION("The netdisk kernel driver module");
