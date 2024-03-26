//
// libnetdisk protocol definitons
//
// Copyright (C) Tom Cully 2024
// Licensed under the MIT License (see LICENSE in root of project)
//
#include "packet_posix.h"

#include "logger.h"
#include "shared/packet.h"

int packet_create_server_socket(int *socket_fd, struct sockaddr_in *addr) {
  // Create socket
  *socket_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (*socket_fd < 0) {
    return NETDISK_PACKET_SOCKET_CREATE_FAILED;
  }

  int enable = 1;
  if (setsockopt(*socket_fd, IPPROTO_TCP, TCP_NODELAY, (void *)&enable, sizeof(enable)) < 0) {
    perror("setsockopt TCP_NODELAY");
    return NETDISK_PACKET_SOCKET_CREATE_FAILED;
  }

  // Bind the socket with the server address
  if (bind(*socket_fd, (const struct sockaddr *)addr, sizeof(*addr)) < 0) {
    return NETDISK_PACKET_SOCKET_BIND_FAILED;
  }

  // Listen on the socket for incoming connections (16 backlog)
  if (listen(*socket_fd, 16) < 0) {
    return NETDISK_PACKET_SOCKET_LISTEN_FAILED;
  }

  return NETDISK_PACKET_SOCKET_OK;
}

int packet_create_client_socket(int *socket_fd, struct sockaddr_in *addr) {
  // Create socket
  *socket_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (*socket_fd < 0) {
    return NETDISK_PACKET_SOCKET_CREATE_FAILED;
  }

  int enable = 1;
  if (setsockopt(*socket_fd, IPPROTO_TCP, TCP_NODELAY, (void *)&enable, sizeof(enable)) < 0) {
    perror("setsockopt TCP_NODELAY");
    return NETDISK_PACKET_SOCKET_CREATE_FAILED;
  }

  // Connect the socket to the specified address
  if (connect(*socket_fd, (const struct sockaddr *)addr, sizeof(*addr)) < 0) {
    close(*socket_fd);  // Close the socket on failure
    return NETDISK_PACKET_SOCKET_CONNECT_FAILED;
  }

  return NETDISK_PACKET_SOCKET_OK;
}

int packet_destroy_socket(int socket_fd) {
  close(socket_fd);

  return NETDISK_PACKET_SOCKET_OK;
}

ssize_t packet_send(int socket_fd, const uint8_t *buffer, size_t size) {
  ssize_t total_sent = 0;
  ssize_t sent = 0;

  while (total_sent < size) {
    sent = send(socket_fd, buffer + total_sent, size - total_sent, 0);

    if (sent <= 0) {
      // Error or connection closed by peer
      log_error("TCP: Error %d", sent);
      return -1;
    }

    total_sent += sent;
  }

  return total_sent;
}

ssize_t packet_recv(int socket_fd, uint8_t *buffer, size_t size, int timeout_ms) {
  ssize_t total_received = 0;
  ssize_t received = 0;
  struct timeval timeout;

  // Set the socket timeout for receiving
  timeout.tv_sec = timeout_ms / 1000;
  timeout.tv_usec = (timeout_ms % 1000) * 1000;
  setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof timeout);

  while (total_received < size) {
    received = recv(socket_fd, buffer + total_received, size - total_received, MSG_WAITALL);

    if (received == 0) {
      // Connection closed
      break;
    } else if (received < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // Timeout
        return -999;
      } else {
        // Other errors
        return -1;
      }
    }

    total_received += received;
  }

  return total_received;
}
