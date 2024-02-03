//
// netdiskd main
//
// Copyright (C) Tom Cully 2024
// Licensed under the MIT License (see LICENSE in root of project)
//
#ifndef NETDISK_MAIN
#define NETDISK_MAIN

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "logger.h"
#include "main.h"
#include "packet.h"
#include "random.h"
#include "tiny-AES-c/aes.h"

#define NETDISK_SESSION_STATE_INITIAL 0
#define NETDISK_SESSION_STATE_IV 1
#define NETDISK_SESSION_STATE_HANDSHAKE 2
#define NETDISK_SESSION_STATE_READY 3

typedef struct session {
  pthread_t thread_id;
  int socket_fd;
  struct sockaddr_in remote_addr;
  uint8_t state;
  struct AES_ctx aes_context;
  uint64_t node_id;
  uint8_t* buffer;
} session_t;

void signal_stop(int signum);
void* handle_connection(void* arg);
bool process_packet(session_t* session, packet_header_t* header, uint8_t* data);
ssize_t recv_exact_with_timeout(int socket_fd, uint8_t* buffer, size_t size, int timeout_ms);

#endif