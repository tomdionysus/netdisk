//
// libnetdisk protocol definitons
//
// Copyright (C) Tom Cully 2024
// Licensed under the MIT License (see LICENSE in root of project)
//
#include "packet.h"

const uint8_t NETDISK_MAGIC_NUMBER[] = {0x4E, 0x54, 0x44, 0x53, 0x4B};

void packet_handshake_init(packet_handshake_t *packet) {
  memset(packet, 0, sizeof(packet_handshake_t));

  // Initialize magic array
  memcpy(packet->magic, NETDISK_MAGIC_NUMBER, NETDISK_MAGIC_NUMBER_LENGTH);

  // Initialize version
  packet->version.major = NETDISK_VERSION_MAJOR;
  packet->version.minor = NETDISK_VERSION_MINOR;
  packet->version.patch = NETDISK_VERSION_PATCH;
}

bool packet_magic_check(packet_handshake_t *packet) { return memcmp(packet->magic, NETDISK_MAGIC_NUMBER, NETDISK_MAGIC_NUMBER_LENGTH) == 0; }

bool packet_version_check(packet_handshake_t *packet, bool strict) {
  return packet->version.major == NETDISK_VERSION_MAJOR && packet->version.minor == NETDISK_VERSION_MINOR &&
         (!strict || packet->version.patch == NETDISK_VERSION_PATCH);
}

const char *packet_operation_to_str(uint16_t command) {
  switch (command) {
    case NETDISK_COMMAND_INFO:
      return "NETDISK_COMMAND_INFO";
    case NETDISK_COMMAND_READ:
      return "NETDISK_COMMAND_READ";
    case NETDISK_COMMAND_WRITE:
      return "NETDISK_COMMAND_WRITE";
    case NETDISK_REPLY_OK:
      return "NETDISK_REPLY_OK";
    case NETDISK_REPLY_INFO:
      return "NETDISK_REPLY_INFO";
    case NETDISK_REPLY_READ_ONLY:
      return "NETDISK_REPLY_READ_ONLY";
    case NETDISK_REPLY_OUT_OF_RANGE:
      return "NETDISK_REPLY_OUT_OF_RANGE";
    case NETDISK_REPLY_UNKNOWN_COMMAND:
      return "NETDISK_REPLY_UNKNOWN_COMMAND";
    case NETDISK_REPLY_ERROR:
      return "NETDISK_REPLY_ERROR";
    default:
      return "Unknown Operation";
  }
}