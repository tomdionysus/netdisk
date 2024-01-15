//
// libnetdisk protocol definitons
//
// Copyright (C) Tom Cully 2024
// Licensed under the MIT License (see LICENSE in root of project)
//
#include "packet.h"

#include "logger.h"

const uint8_t NETDISK_MAGIC_NUMBER[] = {0x4E, 0x54, 0x44, 0x53, 0x4B};

int packet_create_socket(int *socket_fd, struct sockaddr_in *addr) {
  // Create socket
  *socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (*socket_fd < 0) {
    return NETDISK_PACKET_SOCKET_CREATE_FAILED;
  }

  // Bind the socket with the server address
  if (bind(*socket_fd, (const struct sockaddr *)addr, sizeof(*addr)) < 0) {
    return NETDISK_PACKET_SOCKET_BIND_FAILED;
  }

  return NETDISK_PACKET_SOCKET_OK;
}

int packet_destroy_socket(int socket_fd) {
  close(socket_fd);

  return NETDISK_PACKET_SOCKET_OK;
}

void packet_init(packet_t *packet) {
  // Set all to zero
  memset(packet, 0, sizeof(packet_t));

  // Initialize magic array
  memcpy(packet->fields.magic, NETDISK_MAGIC_NUMBER, sizeof(NETDISK_MAGIC_NUMBER));

  // Initialize version
  packet->fields.version.major = NETDISK_VERSION_MAJOR;
  packet->fields.version.minor = NETDISK_VERSION_MINOR;
  packet->fields.version.patch = NETDISK_VERSION_PATCH;

  // Timestamp
  packet->fields.timestamp = time(NULL);
}

bool packet_magic_check(packet_t *packet) { return memcmp(packet->fields.magic, NETDISK_MAGIC_NUMBER, sizeof(NETDISK_MAGIC_NUMBER)) == 0; }

bool packet_version_check(packet_t *packet, bool strict) {
  return packet->fields.version.major == NETDISK_VERSION_MAJOR && packet->fields.version.minor == NETDISK_VERSION_MINOR &&
         (!strict || packet->fields.version.patch == NETDISK_VERSION_PATCH);
}

int packet_send(int socket_fd, packet_t *packet, uint8_t *key, struct sockaddr_in *addr) {
  // Initialise IV
  random_get(packet->iv, NETDISK_KEY_SIZE);

  // Do encrpytion
  struct AES_ctx ctx;
  AES_init_ctx_iv(&ctx, key, packet->iv);
  AES_CBC_encrypt_buffer(&ctx, (uint8_t *)&(packet->data), sizeof(packet_t) - NETDISK_KEY_SIZE);

  // Send the packet
  ssize_t sent_len;
  sent_len = sendto(socket_fd, (const char *)packet, sizeof(packet_t), 0, (struct sockaddr *)addr, sizeof(struct sockaddr));

  if (sent_len == -1) {
    return NETDISK_PACKET_STATUS_SEND_FAILED;
  }

  // All good
  return NETDISK_PACKET_STATUS_OK;
}

int packet_recv(int socket_fd, packet_t *packet, uint8_t *key, bool strict_version, struct sockaddr_in *addr) {
  // Wait for data with timeout
  struct timeval tv;
  fd_set readfds;
  int retval;

  // Set timeout for select (30s)
  tv.tv_sec = 30;
  tv.tv_usec = 0;

  // Clear the set and add our socket to it
  FD_ZERO(&readfds);
  FD_SET(socket_fd, &readfds);

  // Do the wait
  retval = select(socket_fd + 1, &readfds, NULL, NULL, &tv);
  if (retval == -1) {
    if (errno == EINTR) return NETDISK_PACKET_STATUS_INTERRUPT;
    return NETDISK_PACKET_STATUS_UNKNOWN_ERROR;
  } else if (retval == 0) {
    // Timeout occurred
    return NETDISK_PACKET_STATUS_NO_PACKET;
  }

  // Do the receive
  socklen_t socket_addr_len = sizeof(struct sockaddr_in);
  ssize_t recv_len = recvfrom(socket_fd, (char *)packet, sizeof(packet_t), MSG_WAITALL, (struct sockaddr *)addr, &socket_addr_len);

  // Timeout, no packet received
  if (recv_len == -1) {
    return NETDISK_PACKET_STATUS_UNKNOWN_ERROR;
  }

  // Check packet size
  if (recv_len != sizeof(packet_t)) return NETDISK_PACKET_STATUS_BAD_LENGTH;

  // Decrypt packet
  struct AES_ctx ctx;
  AES_init_ctx_iv(&ctx, key, packet->iv);
  AES_CBC_decrypt_buffer(&ctx, (uint8_t *)&(packet->data), sizeof(packet_t) - NETDISK_KEY_SIZE);

  // Check Magic Number (Key is OK)
  if (!packet_magic_check(packet)) return NETDISK_PACKET_STATUS_BAD_KEY;

  // Check version
  if (!packet_version_check(packet, strict_version)) return NETDISK_PACKET_STATUS_BAD_VERSION;

  // All good
  return NETDISK_PACKET_STATUS_OK;
}