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
#include "packet.h"

// Externs
extern netdisk_config_t config;
extern struct socket *client_socket;

// Thread pointer
static struct task_struct *receive_thread = NULL;

session_t *session;

static int run_receive_thread(void *data) {
  // Setup session
  session = kmalloc(sizeof(session_t), GFP_KERNEL);
  session->socket_fd = client_socket;
  session->state = NETDISK_SESSION_STATE_INITIAL;
  session->buffer = kmalloc(NETDISK_MAX_PACKET_SIZE, GFP_KERNEL);

  bool running = true;
  ssize_t recvlen;

  packet_handshake_t *packet;
  packet_header_t *header;

  while (!kthread_should_stop() && running) {
    switch (session->state) {
      case NETDISK_SESSION_STATE_INITIAL:
        // Initial state.
        get_random_bytes(session->buffer, NETDISK_KEY_SIZE);
        // Setup TX AES Context
        AES_init_ctx_iv(&session->tx_aes_context, config.key, session->buffer);
        // Send IV
        packet_send(session->socket_fd, session->buffer, NETDISK_KEY_SIZE);
        // Set State
        session->state = NETDISK_SESSION_STATE_IV;
        break;
      case NETDISK_SESSION_STATE_IV:
        // Wait for other side of IV
        recvlen = packet_recv(session->socket_fd, session->buffer, NETDISK_KEY_SIZE, 5000);
        if (recvlen == NETDISK_KEY_SIZE) {
          // Setup RX AES Context
          AES_init_ctx_iv(&session->rx_aes_context, config.key, session->buffer);
          // Init Handshake, Create NodeID
          packet = (packet_handshake_t *)session->buffer;
          packet_handshake_init(packet);
          // Create a random node ID
          get_random_bytes((uint8_t *)&packet->node_id, sizeof(packet->node_id));
          // Encrypt
          AES_CBC_encrypt_buffer(&session->tx_aes_context, session->buffer, sizeof(packet_handshake_t));
          // Send Handshake
          ssize_t bytes_sent = packet_send(session->socket_fd, session->buffer, sizeof(packet_handshake_t));
          if (bytes_sent < sizeof(packet_handshake_t)) {
            // Handle the error case
            printk(KERN_ERR "netdisk: send failed, closing connection");
            running = false;
          }
          // Set State
          session->state = NETDISK_SESSION_STATE_HANDSHAKE;
        } else if (recvlen == -999) {
          printk(KERN_ALERT "netdisk: Timeout, closing connection");
          running = false;
        } else {
          printk(KERN_ALERT "netdisk: Error, closing connection");
          running = false;
        }
        break;
      case NETDISK_SESSION_STATE_HANDSHAKE:
        // Wait for handshake packet
        recvlen = packet_recv(session->socket_fd, session->buffer, sizeof(packet_handshake_t), 5000);
        if (recvlen == sizeof(packet_handshake_t)) {
          // Decrypt
          AES_CBC_decrypt_buffer(&session->rx_aes_context, session->buffer, recvlen);
          // Check Magic number
          packet = (packet_handshake_t *)session->buffer;
          if (!packet_magic_check(packet)) {
            printk(KERN_ALERT "netdisk: Bad magic number from server, disconnecting");
            running = false;
            break;
          }
          // Check Version
          if (!packet_version_check(packet, false)) {
            printk(KERN_ALERT "netdisk: Incompatible version from server, disconnecting");
            running = false;
            break;
          }
          // Get NodeID
          session->node_id = packet->node_id;
          // Set state ready
          session->state = NETDISK_SESSION_STATE_READY;
        } else if (recvlen == -999) {
          printk(KERN_ALERT "netdisk: Timeout, closing connection");
          running = false;
        } else {
          running = false;
        }
        break;
      case NETDISK_SESSION_STATE_READY:
        // Read a header, then a packet of that length
        recvlen = packet_recv(session->socket_fd, session->buffer, sizeof(packet_header_t), 10000);
        if (recvlen == sizeof(packet_header_t)) {
          // Decrypt
          AES_CBC_decrypt_buffer(&session->rx_aes_context, session->buffer, recvlen);
          header = (packet_header_t *)session->buffer;
          // Check we have enough buffer
          if (header->length > NETDISK_MAX_PACKET_SIZE) {
            printk(KERN_ALERT "netdisk: Packet too large (%d bytes, limit %d)", header->length, NETDISK_MAX_PACKET_SIZE);
            running = false;
            break;
          }
          // If there's more data, receive it
          if (header->length > 0) {
            if (packet_recv(session->socket_fd, (uint8_t *)session->buffer + sizeof(packet_header_t), header->length, 10000) != header->length) {
              printk(KERN_ALERT "netdisk: Timeout receiving packet data (%d bytes)", header->length);
              running = false;
              break;
            }
            // And Decrypt it
            AES_CBC_decrypt_buffer(&session->rx_aes_context, (uint8_t *)session->buffer + sizeof(packet_header_t), header->length);
          }
          // Process the packet, stop if return true
          if (process_packet(session, header, header->length == 0 ? NULL : (uint8_t *)session->buffer + sizeof(packet_header_t))) {
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

  // Free the session
  kfree(session->buffer);
  kfree(session);

  receive_thread = NULL;

  return 0;
}

// Create receive_thread
int receive_thread_start(void) {
  if (receive_thread != NULL) {
    printk(KERN_ALERT "netdisk: receive_thread_start called but thread already started\n");
    return 0;
  }

  receive_thread = kthread_run(run_receive_thread, NULL, "run_receive_thread");
  if (IS_ERR(receive_thread)) {
    printk(KERN_INFO "netdisk: failed to create run_receive_thread\n");
    return PTR_ERR(receive_thread);
  }

  return 0;
}

bool process_packet(session_t *session, packet_header_t *header, uint8_t *data) {
  // printk(KERN_NOTICE "netdisk: Incoming packet %s, Transaction %llu, Block %llu, Length %u\n", packet_reply_to_str(header->operation), header->transaction_id,
  //        header->block_id, header->length);

  switch (header->operation) {
    case NETDISK_REPLY_OK:
      netdisk_complete_chunk(header->transaction_id, header->block_id, data, header->length);
      break;
    case NETDISK_REPLY_READ_ONLY:
    case NETDISK_REPLY_OUT_OF_RANGE:
    case NETDISK_REPLY_ERROR:
      netdisk_error_chunk(header->transaction_id, header->block_id, header->operation);
      break;
    default:
      printk(KERN_NOTICE "netdisk: Received unknown operation %d\n", header->operation);
  }

  return false;
}

void receive_thread_stop(void) {
  if (!receive_thread) {
    return;
  }

  kthread_stop(receive_thread);
  receive_thread = NULL;
}
