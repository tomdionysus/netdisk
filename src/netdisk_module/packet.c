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
#include "packet.h"
#include "util.h"

const u8 NETDISK_MAGIC_NUMBER[] = {0x4E, 0x54, 0x44, 0x53, 0x4B};

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
	struct timespec64 ts;
	ktime_get_real_ts64(&ts);
  packet->fields.timestamp = (long long)ts.tv_sec;
}

bool packet_magic_check(packet_t *packet) { return memcmp(packet->fields.magic, NETDISK_MAGIC_NUMBER, sizeof(NETDISK_MAGIC_NUMBER)) == 0; }

bool packet_version_check(packet_t *packet, bool strict) {
  return packet->fields.version.major == NETDISK_VERSION_MAJOR && packet->fields.version.minor == NETDISK_VERSION_MINOR &&
         (!strict || packet->fields.version.patch == NETDISK_VERSION_PATCH);
}

int packet_send(packet_t *packet, u8 *key, struct sockaddr_in *addr) {
  // printk(KERN_DEBUG "netdisk: sending %s from %pI4:%u\n", packet_command_to_str(packet->fields.command), &addr->sin_addr, ntohs(addr->sin_port));

  // Initialise IV
  get_random_bytes(packet->iv, NETDISK_KEY_SIZE);

  // Do encrpytion
  struct AES_ctx ctx;
  AES_init_ctx_iv(&ctx, key, packet->iv);
  AES_CBC_encrypt_buffer(&ctx, (u8 *)&(packet->data), sizeof(packet_t) - NETDISK_KEY_SIZE);

  // Send the packet
  if (send_udp_packet((const char *)packet, sizeof(packet_t), addr) != sizeof(packet_t)) {
    return NETDISK_PACKET_STATUS_SEND_FAILED;
  }

  // All good
  return NETDISK_PACKET_STATUS_OK;
}

int packet_recv(packet_t *packet, u8 *key, bool strict_version, struct sockaddr_in *addr) {
  // Do the receive
  ssize_t recv_len = receive_udp_packet((char *)packet, sizeof(packet_t), addr); 

  // Timeout, no packet received
  if (recv_len == -1) {
    return NETDISK_PACKET_STATUS_UNKNOWN_ERROR;
  }

  // Check packet size
  if (recv_len != sizeof(packet_t)) return NETDISK_PACKET_STATUS_BAD_LENGTH;

  // Decrypt packet
  struct AES_ctx ctx;
  AES_init_ctx_iv(&ctx, key, packet->iv);
  AES_CBC_decrypt_buffer(&ctx, (u8 *)&(packet->data), sizeof(packet_t) - NETDISK_KEY_SIZE);

  // Check Magic Number (Key is OK)
  if (!packet_magic_check(packet)) return NETDISK_PACKET_STATUS_BAD_KEY;

  // Check version
  if (!packet_version_check(packet, strict_version)) return NETDISK_PACKET_STATUS_BAD_VERSION;

  // All good
  return NETDISK_PACKET_STATUS_OK;
}

const char *packet_command_to_str(u16 command) {
  switch(command) {
    case NETDISK_COMMAND_START: return "NETDISK_COMMAND_START";
    case NETDISK_COMMAND_STOP: return "NETDISK_COMMAND_STOP";
    case NETDISK_COMMAND_READ: return "NETDISK_COMMAND_READ";
    case NETDISK_COMMAND_WRITE: return "NETDISK_COMMAND_WRITE";
    default: return "Unknown Command";
  }
}

const char *packet_reply_to_str(u16 reply) {
  switch(reply) {
    case NETDISK_REPLY_OK: return "NETDISK_REPLY_OK";
    case NETDISK_REPLY_READ_OK: return "NETDISK_REPLY_READ_OK";
    case NETDISK_REPLY_WRITE_OK: return "NETDISK_REPLY_WRITE_OK";
    case NETDISK_REPLY_READ_ONLY: return "NETDISK_REPLY_READ_ONLY";
    case NETDISK_REPLY_OUT_OF_RANGE: return "NETDISK_REPLY_OUT_OF_RANGE";
    case NETDISK_REPLY_ERROR: return "NETDISK_REPLY_ERROR";
    default: return "Unknown Reply";
  }

}



