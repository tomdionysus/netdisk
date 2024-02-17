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
#include "receive_thread.h"

#include "module.h"
#include "netdisk_device.h"
#include "packet_kernel.h"

// Externs
extern netdisk_config_t config;

// Thread pointer
static struct task_struct *receive_thread = NULL;

static int run_receive_thread(void *data) {
  session_t *session = (session_t *)data;

  bool running = true;
  ssize_t recvlen;

  uint8_t iv[NETDISK_KEY_SIZE];
  packet_handshake_t handshake_raw;
  packet_handshake_t *handshake = &handshake_raw;
  packet_header_t header_raw;
  packet_header_t *header = &header_raw;

  while (!kthread_should_stop() && running) {
    switch (session->state) {
      case NETDISK_SESSION_STATE_INITIAL:
        // Initial state.
        get_random_bytes(&iv, NETDISK_KEY_SIZE);
        // Setup TX AES Context
        AES_CBC_set_tx_iv(session->aes_context, (uint8_t *)&iv);
        // Send IV
        packet_send(session->socket_fd, (uint8_t *)&iv, NETDISK_KEY_SIZE);
        // Set State
        session->state = NETDISK_SESSION_STATE_IV;
        break;
      case NETDISK_SESSION_STATE_IV:
        // Wait for other side of IV
        recvlen = packet_recv(session->socket_fd, (uint8_t *)&iv, NETDISK_KEY_SIZE, 5000);
        if (recvlen == NETDISK_KEY_SIZE) {
          // Setup RX AES Context
          AES_CBC_set_rx_iv(session->aes_context, (uint8_t *)&iv);
          // Init Handshake, Create NodeID
          packet_handshake_init(handshake);
          // Create a random node ID
          get_random_bytes((uint8_t *)&handshake->node_id, sizeof(handshake->node_id));
          // Encrypt
          AES_CBC_encrypt_buffer(session->aes_context, (uint8_t *)handshake, (uint8_t *)handshake, sizeof(packet_handshake_t));
          // Send Handshake
          ssize_t bytes_sent = packet_send(session->socket_fd, (uint8_t *)handshake, sizeof(packet_handshake_t));
          if (bytes_sent < sizeof(packet_handshake_t)) {
            // Handle the error case
            printk(KERN_ERR "netdisk: handshake send failed, closing connection");
            running = false;
          }
          // Set State
          session->state = NETDISK_SESSION_STATE_HANDSHAKE;
        } else if (recvlen == -999) {
          printk(KERN_ERR "netdisk: receive IV timeout, closing connection");
          running = false;
        } else {
          printk(KERN_ERR "netdisk: recieve IV error, closing connection");
          running = false;
        }
        break;
      case NETDISK_SESSION_STATE_HANDSHAKE:
        // Wait for handshake handshake
        recvlen = packet_recv(session->socket_fd, (uint8_t *)handshake, sizeof(packet_handshake_t), 5000);
        if (recvlen == sizeof(packet_handshake_t)) {
          // Decrypt
          AES_CBC_decrypt_buffer(session->aes_context, (uint8_t *)handshake, (uint8_t *)handshake, recvlen);
          // Check Magic number
          if (!packet_magic_check(handshake)) {
            printk(KERN_ERR "netdisk: bad magic number from server (likely wrong encryption key), closing connection");
            running = false;
            break;
          }
          // Check Version
          if (!packet_version_check(handshake, false)) {
            printk(KERN_ERR "netdisk: incompatible version from server, closing connection");
            running = false;
            break;
          }
          // Get NodeID
          session->node_id = handshake->node_id;
          // Set state ready
          session->state = NETDISK_SESSION_STATE_READY;
        } else if (recvlen == -999) {
          printk(KERN_ERR "netdisk: receive handshake timeout, closing connection");
          running = false;
        } else {
          running = false;
        }
        break;
      case NETDISK_SESSION_STATE_READY:
        // Read a header, then a handshake of that length
        recvlen = packet_recv(session->socket_fd, (uint8_t *)header, sizeof(packet_header_t), 10000);
        if (recvlen == sizeof(packet_header_t)) {
          // Decrypt
          AES_CBC_decrypt_buffer(session->aes_context, (uint8_t *)header, (uint8_t *)header, sizeof(packet_header_t));
          // Process the handshake, stop if return true
          if (process_packet(session, header)) {
            running = false;
            break;
          }
        } else if (recvlen == -999) {
          // Do Nothing
        } else {
          running = false;
        }
        break;
    }
  }

  // If any transactions are left, they should fail
  error_all_transactions();
  release_all_transactions();

  receive_thread = NULL;

  return 0;
}

// Create receive_thread
int receive_thread_start(session_t *session) {
  if (receive_thread != NULL) {
    printk(KERN_ALERT "netdisk: receive_thread_start called but thread already started\n");
    return 0;
  }

  receive_thread = kthread_run(run_receive_thread, session, "run_receive_thread");
  if (IS_ERR(receive_thread)) {
    printk(KERN_INFO "netdisk: failed to create run_receive_thread\n");
    return PTR_ERR(receive_thread);
  }

  sched_set_fifo(receive_thread);

  return 0;
}

bool process_packet(session_t *session, packet_header_t *header) {
  // printk(KERN_NOTICE "netdisk: Incoming %s, Transaction %llu, Block %llu, Length %u\n", packet_reply_to_str(header->operation), header->transaction_id,
  //        header->block_id, header->length);

  switch (header->operation) {
    case NETDISK_REPLY_OK:
      netdisk_complete_chunk(session, header);
      break;
    case NETDISK_REPLY_READ_ONLY:
    case NETDISK_REPLY_OUT_OF_RANGE:
    case NETDISK_REPLY_ERROR:
      netdisk_error_chunk(header->transaction_id, header->block_id, header->operation);
      break;
    default:
      printk(KERN_ALERT "netdisk: Received unknown operation %d\n", header->operation);
  }

  return false;
}

void receive_thread_stop(session_t *session) {
  if (!receive_thread) {
    return;
  }

  kthread_stop(receive_thread);
  receive_thread = NULL;
}
