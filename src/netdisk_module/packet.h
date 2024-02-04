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
#ifndef PACKET
#define PACKET

#include <linux/net.h>
#include <net/sock.h>
#include <linux/types.h>
#include <linux/time.h>
#include <linux/ktime.h>
#include <linux/timekeeping.h>
#include <linux/random.h>

#include "aes.h"
#include "udp_socket.h"

#define NETDISK_DEFAULT_PORT 26547

#define NETDISK_BLOCK_SIZE 512
#define NETDISK_BLOCK_SHIFT 9
#define NETDISK_HEADER_SIZE 64
#define NETDISK_MAX_PACKET_SIZE (NETDISK_BLOCK_SIZE + NETDISK_HEADER_SIZE)
#define NETDISK_KEY_SIZE 32
#define NETDISK_TOTAL_PACKET_SIZE (NETDISK_MAX_PACKET_SIZE + NETDISK_KEY_SIZE)

#define NETDISK_VERSION_MAJOR 0x00
#define NETDISK_VERSION_MINOR 0x00
#define NETDISK_VERSION_PATCH 0x01

#define NETDISK_COMMAND_START 0x0001
#define NETDISK_COMMAND_STOP 0x0002
#define NETDISK_COMMAND_READ 0x0003
#define NETDISK_COMMAND_WRITE 0x0004

#define NETDISK_REPLY_OK 0x8001
#define NETDISK_REPLY_READ_ONLY 0x8002
#define NETDISK_REPLY_OUT_OF_RANGE 0x8003
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

extern const u8 NETDISK_MAGIC_NUMBER[];

#pragma pack(push, 1)

typedef struct packet {
  u8 iv[NETDISK_KEY_SIZE];

  union {
    u8 data[NETDISK_MAX_PACKET_SIZE];
    struct fields {
      u8 magic[5];
      struct version {
        u8 major;
        u8 minor;
        u8 patch;
      } version;
      u16 command;
      u16 reply;
      u32 sequence;
      u64 timestamp;
      u64 block_offset;
      u64 user_data;
      u8 _reserved[24];
      u8 payload[NETDISK_BLOCK_SIZE];
    } fields;
  };

  struct list_head rx_tx_list;
  struct sockaddr_in addr;
} packet_t;

typedef struct command_start_stop_payload {
  u64 node_id;
} command_start_stop_payload_t;

#pragma pack(pop)

void packet_init(packet_t* packet);
bool packet_magic_check(packet_t* packet);
bool packet_version_check(packet_t* packet, bool strict);
int packet_send(packet_t* packet, u8* key);
int packet_recv(packet_t* packet, u8* key, bool strict_version);

const char *packet_command_to_str(u16 command);
const char *packet_reply_to_str(u16 reply);

#endif
