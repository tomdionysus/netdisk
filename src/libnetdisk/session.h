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
#include "packet_queue.h"
#include "tiny-AES-c/aes.h"

typedef struct session {
  int socket_fd;
  struct sockaddr_in remote_addr;
  uint8_t state;
  struct AES_ctx rx_aes_context;
  struct AES_ctx tx_aes_context;

  pthread_t main_thread_id;
  pthread_t send_thread_id;

  packet_queue_t* send_queue;

  // pthread_t recv_thread_id;
  // packet_queue_t* recv_queue;

  uint64_t node_id;

  char remote_addr_str[32];
} session_t;

session_t *session_create(int socket_fd, struct sockaddr_in remote_addr, void *(main_thread)(void *arg), void *(send_thread)(void *arg));
void session_release(session_t* session);

#endif