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

#include <linux/blk-mq.h>
#include <linux/ktime.h>
#include <linux/net.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/timekeeping.h>
#include <linux/types.h>
#include <net/sock.h>

#include "aes.h"
#include "transaction.h"
#include "util.h"

#define NETDISK_DEFAULT_PORT 26547

#define NETDISK_BLOCK_SIZE 512
#define NETDISK_BLOCK_SHIFT 9
#define NETDISK_HEADER_SIZE 64
#define NETDISK_MAX_PACKET_SIZE ((1024*1024)+32)
#define NETDISK_KEY_SIZE 32

#define NETDISK_VERSION_MAJOR 0x00
#define NETDISK_VERSION_MINOR 0x00
#define NETDISK_VERSION_PATCH 0x01

#define NETDISK_SESSION_STATE_INITIAL 0
#define NETDISK_SESSION_STATE_IV 1
#define NETDISK_SESSION_STATE_HANDSHAKE 2
#define NETDISK_SESSION_STATE_READY 3

#define NETDISK_COMMAND_INFO 0x0001
#define NETDISK_COMMAND_READ 0x0002
#define NETDISK_COMMAND_WRITE 0x0003

#define NETDISK_REPLY_OK 0x8001
#define NETDISK_REPLY_INFO 0x8002
#define NETDISK_REPLY_READ_ONLY 0x8101
#define NETDISK_REPLY_OUT_OF_RANGE 0x8102
#define NETDISK_REPLY_UNKNOWN_COMMAND 0xFFFE
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
#define NETDISK_PACKET_SOCKET_CONNECT_FAILED 4

extern const uint8_t NETDISK_MAGIC_NUMBER[];
#define NETDISK_MAGIC_NUMBER_LENGTH 4

#pragma pack(push, 1)

typedef struct session {
  struct socket* socket_fd;
  struct sockaddr_in remote_addr;
  uint8_t state;
  struct AES_ctx rx_aes_context;
  struct AES_ctx tx_aes_context;
  uint64_t node_id;
  char address_str[32];
  uint8_t* buffer;
} session_t;

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

// Should be exactly 32 bytes long.
typedef struct packet_header {
  uint16_t operation;       // The operation (commands, replies, errors etc)
  uint16_t flags;           // (Unused, Reserved) Flags for the packet
  uint64_t block_id;        // The block_id (or block offset) to be read or written
  uint32_t block_length;    // The length of the block to be read or written
  uint64_t transaction_id;  // (Unused) The transaction ID for this read or write
  uint32_t user_data;       // (Unused) Any user data to be included in the reply.
  uint32_t length;          // The length of the data following this packet
} packet_header_t;

#pragma pack(pop)

int packet_create_client_socket(struct socket** tcp_socket, struct sockaddr_in* addr);
int packet_destroy_socket(struct socket* tcp_socket);

ssize_t packet_recv(struct socket* tcp_socket, uint8_t* buffer, size_t size, int timeout_ms);
ssize_t packet_send(struct socket* tcp_socket, uint8_t* buffer, size_t size);

void send_chunk_request(struct socket* tcp_socket, struct AES_ctx* context, transaction_t* trans, chunk_t* chunk);

void packet_handshake_init(packet_handshake_t* packet);
bool packet_magic_check(packet_handshake_t* packet);
bool packet_version_check(packet_handshake_t* packet, bool strict);

const char* packet_command_to_str(u16 command);
const char* packet_reply_to_str(u16 reply);

#endif
