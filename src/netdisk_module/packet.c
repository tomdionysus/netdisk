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
#include "packet.h"

const u8 NETDISK_MAGIC_NUMBER[] = {0x4E, 0x54, 0x44, 0x53, 0x4B};

int packet_create_client_socket(struct socket **tcp_socket, struct sockaddr_in *addr) {
  int ret;

  // Create TCP socket
  ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, tcp_socket);
  if (ret < 0) {
    printk(KERN_ERR "Error creating socket: %d\n", ret);
    return ret;
  }

  // Connect the socket to the server address
  ret = kernel_connect(*tcp_socket, (struct sockaddr *)addr, sizeof(*addr), 0);
  if (ret < 0) {
    sock_release(*tcp_socket);
    printk(KERN_ERR "Error connecting socket: %d\n", ret);
    return ret;
  }

  return 0;
}

int packet_destroy_socket(struct socket *tcp_socket) {
  if (tcp_socket) {
    sock_release(tcp_socket);
    tcp_socket = NULL;
  }
  return 0;
}

void packet_handshake_init(packet_handshake_t *packet) {
  memset(packet, 0, sizeof(packet_handshake_t));

  // Initialize magic array
  memcpy(packet->magic, NETDISK_MAGIC_NUMBER, NETDISK_MAGIC_NUMBER_LENGTH);

  // Initialize version
  packet->version.major = NETDISK_VERSION_MAJOR;
  packet->version.minor = NETDISK_VERSION_MINOR;
  packet->version.patch = NETDISK_VERSION_PATCH;
}

bool packet_magic_check(packet_handshake_t *packet) { return memcmp(packet->magic, NETDISK_MAGIC_NUMBER, NETDISK_MAGIC_NUMBER_LENGTH) == 0; }

bool packet_version_check(packet_handshake_t *packet, bool strict) {
  return packet->version.major == NETDISK_VERSION_MAJOR && packet->version.minor == NETDISK_VERSION_MINOR &&
         (!strict || packet->version.patch == NETDISK_VERSION_PATCH);
}

ssize_t packet_recv(struct socket *tcp_socket, uint8_t *buffer, size_t size, int timeout_ms) {
  struct msghdr msg;
  struct kvec vec;
  size_t total_received = 0;
  int ret;
  long original_timeout = tcp_socket->sk->sk_rcvtimeo;
  long timeout_jiffies = msecs_to_jiffies(timeout_ms);

  // Initialize message and vector structures
  memset(&msg, 0, sizeof(msg));
  vec.iov_base = buffer;
  vec.iov_len = size;

  // Receive loop
  while (total_received < size) {
    // Set the socket to use the timeout
    tcp_socket->sk->sk_rcvtimeo = timeout_jiffies;

    ret = kernel_recvmsg(tcp_socket, &msg, &vec, 1, size - total_received, MSG_WAITALL);

    if (ret == -EAGAIN || ret == -EWOULDBLOCK) {
      // Timeout
      ret = -999;
      break;
    } else if (ret <= 0) {
      // Error or connection closed
      break;
    }

    total_received += ret;
    vec.iov_base = buffer + total_received;
    vec.iov_len = size - total_received;
  }

  // Restore original timeout
  tcp_socket->sk->sk_rcvtimeo = original_timeout;

  return ret < 0 ? ret : total_received;
}

ssize_t packet_send(struct socket *tcp_socket, uint8_t *buffer, size_t size) {
  struct msghdr msg;
  struct kvec vec;
  size_t total_sent = 0;
  int ret;

  // Initialize message and vector structures
  memset(&msg, 0, sizeof(msg));
  vec.iov_base = buffer;
  vec.iov_len = size;

  // Send loop
  while (total_sent < size) {
    ret = kernel_sendmsg(tcp_socket, &msg, &vec, 1, size - total_sent);

    if (ret < 0) {
      // An error occurred during send
      return ret;
    }

    total_sent += ret;
    vec.iov_base = buffer + total_sent;
    vec.iov_len = size - total_sent;
  }

  return total_sent;
}

void send_chunk_request(struct socket *tcp_socket, struct AES_ctx *context, transaction_t *trans, chunk_t *chunk) {
  packet_header_t *header = kmalloc(sizeof(packet_header_t) + chunk->size, GFP_KERNEL);
  void *data = (uint8_t*)header + sizeof(packet_header_t);

  if (rq_data_dir(trans->request) == WRITE) {
    header->operation = NETDISK_COMMAND_WRITE;
    header->length = chunk->size;
    memcpy(data, chunk->buffer, chunk->size);
  } else {
    header->operation = NETDISK_COMMAND_READ;
    header->length = 0;
  }

  header->block_id = chunk->block_id;
  header->transaction_id = trans->id;
  header->user_data = 0;

  if((sizeof(packet_header_t) + header->length) % 16 != 0) {
    printk(KERN_ERR "netdisk: Error packet length is not a multiple of 16: %lu\n", (sizeof(packet_header_t) + header->length));
  }

  printk(KERN_NOTICE "netdisk: Sending Op %s, Transaction %llu, Chunk %llu, Length %u\n", packet_command_to_str(header->operation), trans->id, chunk->block_id, header->length);

  // Encrypt
  AES_CBC_encrypt_buffer(context, (uint8_t *)header, sizeof(packet_header_t) + header->length);

  // Send
  packet_send(tcp_socket, (uint8_t *)header, sizeof(packet_header_t) + header->length);

  kfree(header);
}

const char *packet_command_to_str(u16 command) {
  switch (command) {
    case NETDISK_COMMAND_INFO:
      return "NETDISK_COMMAND_INFO";
    case NETDISK_COMMAND_READ:
      return "NETDISK_COMMAND_READ";
    case NETDISK_COMMAND_WRITE:
      return "NETDISK_COMMAND_WRITE";
    default:
      return "Unknown Command";
  }
}

const char *packet_reply_to_str(u16 reply) {
  switch (reply) {
    case NETDISK_REPLY_OK:
      return "NETDISK_REPLY_OK";
    case NETDISK_REPLY_INFO:
      return "NETDISK_REPLY_INFO";
    case NETDISK_REPLY_READ_ONLY:
      return "NETDISK_REPLY_READ_ONLY";
    case NETDISK_REPLY_OUT_OF_RANGE:
      return "NETDISK_REPLY_OUT_OF_RANGE";
    case NETDISK_REPLY_UNKNOWN_COMMAND:
      return "NETDISK_REPLY_UNKNOWN_COMMAND";
    case NETDISK_REPLY_ERROR:
      return "NETDISK_REPLY_ERROR";
    default:
      return "Unknown Reply";
  }
}
