//
// libnetdisk protocol definitons
//
// Copyright (C) Tom Cully 2024
// Licensed under the MIT License (see LICENSE in root of project)
//
#ifndef NETDISK_PACKET_POSIX
#define NETDISK_PACKET_POSIX

#include <arpa/inet.h>
#include <errno.h>
#include <memory.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/time.h>
#include <time.h>

#include "random.h"
#include "shared/packet.h"

int packet_create_server_socket(int* socket_fd, struct sockaddr_in* addr);
int packet_create_client_socket(int* socket_fd, struct sockaddr_in* addr);
int packet_destroy_socket(int socket_id);

ssize_t packet_send(int socket_fd, const uint8_t* buffer, size_t size);
ssize_t packet_recv(int socket_fd, uint8_t* buffer, size_t size, int timeout_ms);

#endif
