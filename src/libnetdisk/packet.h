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
#define NETDISK_MAX_PACKET_SIZE (NETDISK_BLOCK_SIZE + NETDISK_HEADER_SIZE)
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

#include <arpa/inet.h>
#include <errno.h>
#include <memory.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/time.h>
#include <time.h>

#include "random.h"
#include "tiny-AES-c/aes.h"

extern const uint8_t NETDISK_MAGIC_NUMBER[];

#pragma pack(push, 1)

typedef struct packet {
  uint8_t iv[NETDISK_KEY_SIZE];

  union {
    uint8_t data[NETDISK_MAX_PACKET_SIZE];
    struct fields {
      uint8_t magic[5];
      struct version {
        uint8_t major;
        uint8_t minor;
        uint8_t patch;
      } version;
      uint16_t command;
      uint16_t reply;
      uint32_t sequence;
      uint64_t timestamp;
      uint64_t block_offset;
      uint64_t user_data;
      uint8_t _reserved[24];
      uint8_t payload[NETDISK_BLOCK_SIZE];
    } fields;
  };
} packet_t;

typedef struct command_start_stop_payload {
  uint64_t node_id;
} command_start_stop_payload_t;

#pragma pack(pop)

int packet_create_socket(int* socket_fd, struct sockaddr_in* addr);
int packet_destroy_socket(int socket_id);

void packet_init(packet_t* packet);
bool packet_magic_check(packet_t* packet);
bool packet_version_check(packet_t* packet, bool strict);
int packet_send(int socket_fd, packet_t* packet, uint8_t* key, struct sockaddr_in* addr);
int packet_recv(int socket_fd, packet_t* packet, uint8_t* key, bool strict_version, struct sockaddr_in* addr);

#endif
