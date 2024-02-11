//
// libnetdisk random functions
//
// Copyright (C) Tom Cully 2024
// Licensed under the MIT License (see LICENSE in root of project)
//
#ifndef NETDISK_SESSION
#define NETDISK_SESSION

#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <pthread.h>

#include "shared/packet.h"
#include "random.h"
#include "tiny-AES-c/aes.h"

typedef struct session {
  pthread_t thread_id;
  int socket_fd;
  struct sockaddr_in remote_addr;
  char remote_addr_str[32];
  uint8_t state;
  struct AES_ctx rx_aes_context;
  struct AES_ctx tx_aes_context;
  uint64_t node_id;
  uint8_t* buffer;
} session_t;

session_t* session_create(int socket_fd, struct sockaddr_in remote_addr, void*(handler)(void* arg));
void session_release(session_t* session);

#endif