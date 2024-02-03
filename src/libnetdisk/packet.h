//
// libnetdisk protocol definitons
//
// Copyright (C) Tom Cully 2024
// Licensed under the MIT License (see LICENSE in root of project)
//
#ifndef NETDISK_PROTOCOL
#define NETDISK_PROTOCOL

#define NETDISK_DEFAULT_PORT 26547

#define NETDISK_BLOCK_SIZE 512
#define NETDISK_BLOCK_SHIFT 9
#define NETDISK_HEADER_SIZE 64
#define NETDISK_MAX_PACKET_SIZE 1024 * 1024
#define NETDISK_KEY_SIZE 32

#define NETDISK_VERSION_MAJOR 0x00
#define NETDISK_VERSION_MINOR 0x00
#define NETDISK_VERSION_PATCH 0x01

#define NETDISK_COMMAND_START 0x0001
#define NETDISK_COMMAND_STOP 0x0002
#define NETDISK_COMMAND_READ 0x0003
#define NETDISK_COMMAND_WRITE 0x0004

#define NETDISK_REPLY_OK 0x8001
#define NETDISK_REPLY_READ_OK 0x8002
#define NETDISK_REPLY_WRITE_OK 0x8003
#define NETDISK_REPLY_READ_ONLY 0x8004
#define NETDISK_REPLY_OUT_OF_RANGE 0x8005
#define NETDISK_REPLY_ERROR 0xFFFF

#define NETDISK_PACKET_STATUS_OK 0
#define NETDISK_PACKET_STATUS_NO_PACKET 1
#define NETDISK_PACKET_STATUS_BAD_KEY 2
#define NETDISK_PACKET_STATUS_BAD_LENGTH 3
#define NETDISK_PACKET_STATUS_BAD_VERSION 4
#define NETDISK_PACKET_STATUS_SEND_FAILED 5
#define NETDISK_PACKET_STATUS_RECV_FAILED 6
#define NETDISK_PACKET_STATUS_INTERRUPT 7
#define NETDISK_PACKET_STATUS_UNKNOWN_ERROR 0xFFFF

#define NETDISK_PACKET_SOCKET_OK 0
#define NETDISK_PACKET_SOCKET_CREATE_FAILED 1
#define NETDISK_PACKET_SOCKET_BIND_FAILED 2
#define NETDISK_PACKET_SOCKET_LISTEN_FAILED 3

#include <arpa/inet.h>
#include <errno.h>
#include <memory.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/time.h>
#include <time.h>

#include "random.h"

extern const uint8_t NETDISK_MAGIC_NUMBER[];

#pragma pack(push, 1)

// Should be exactly 16 bytes long.
typedef struct packet_handshake {
  uint8_t magic[4];
  struct {
    uint8_t major;
    uint8_t minor;
    uint8_t patch;
    uint8_t _reserved;
  } version;
  uint64_t node_id;
} packet_handshake_t;

// Should be exactly 16 bytes long.
typedef struct packet_header {
  uint16_t type;
  uint16_t flags;
  uint32_t length;
  uint32_t block_id;
  uint32_t transaction_id;
} packet_header_t;

#pragma pack(pop)

int packet_create_socket(int* socket_fd, struct sockaddr_in* addr);
int packet_destroy_socket(int socket_id);

void packet_handshake_init(packet_handshake_t* packet);
bool packet_magic_check(packet_handshake_t *packet);
bool packet_version_check(packet_handshake_t *packet, bool strict);

#endif
