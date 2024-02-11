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
#include "packet_kernel.h"

int packet_create_client_socket(struct socket **tcp_socket, struct sockaddr_in *addr) {
  int ret;

  // Create TCP socket
  ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, tcp_socket);
  if (ret < 0) {
    printk(KERN_ERR "netdisk: error creating socket: %d\n", ret);
    return ret;
  }

  // Connect the socket to the server address
  ret = kernel_connect(*tcp_socket, (struct sockaddr *)addr, sizeof(*addr), 0);
  if (ret < 0) {
    sock_release(*tcp_socket);
    printk(KERN_ERR "netdisk: error connecting: %d\n", ret);
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
