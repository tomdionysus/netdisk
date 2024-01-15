//
// netdiskd main
//
// Copyright (C) Tom Cully 2024
// Licensed under the MIT License (see LICENSE in root of project)
//
#include "main.h"

volatile bool running = true;
volatile bool stopping = false;
netdiskd_config_t config;
int socket_fd;
int disk_fd;

int main(int argc, char* argv[]) {
  if (!parse_config(argc, argv, &config)) {
    exit(EXIT_FAILURE);
  }

  log_set_level(config.log_level);

  log_raw("-------------------------");
  log_raw("netdiskd v%d.%d.%d", NETDISK_VERSION_MAJOR, NETDISK_VERSION_MINOR, NETDISK_VERSION_PATCH);
  log_raw("-------------------------");

  if (config.log_level == LOG_LEVEL_DEBUG) dump_config(&config);

  struct sockaddr_in server_addr, client_addr;
  char buffer[NETDISK_MAX_PACKET_SIZE];
  ssize_t recv_len;
  struct timeval tv;

  log_debug("Creating UDP socket...");

  switch (packet_create_socket(&socket_fd, &(config.addr))) {
    case NETDISK_PACKET_SOCKET_OK:
      break;
    case NETDISK_PACKET_SOCKET_CREATE_FAILED:
      log_error("Socket creation failed");
      exit(EXIT_FAILURE);
      break;
    case NETDISK_PACKET_SOCKET_BIND_FAILED:
      log_error("Binding to address %s:%d failed", inet_ntoa(config.addr.sin_addr), ntohs(config.addr.sin_port));
      exit(EXIT_FAILURE);
      break;
  }

  // Start the random number generator
  log_debug("Initialise RNG...");
  if (!random_init()) {
    log_error("Failed to initialise cryptographic random source");
    close(socket_fd);
    exit(EXIT_FAILURE);
  }

  // Open the file/device
  log_debug("Open file or device...");
  if ((disk_fd = open(config.file, config.read_only ? O_RDONLY : O_RDWR)) == -1) {
    log_error("Failed to open file/device %s", config.file);
    close(socket_fd);
    random_shutdown();
    exit(EXIT_FAILURE);
  }

  // Setup CTRL-C (SIGINT) quit
  log_debug("Register SIGINT...");
  struct sigaction sa;
  sa.sa_handler = signal_stop;
  sa.sa_flags = 0;  // or SA_RESTART
  sigemptyset(&sa.sa_mask);

  if (sigaction(SIGINT, &sa, NULL) == -1) {
    log_error("sigaction failed");
    close(socket_fd);
    random_shutdown();
    exit(EXIT_FAILURE);
  }

  // Log Started
  log_info("netdiskd listening on UDP %s:%d", inet_ntoa(config.addr.sin_addr), ntohs(config.addr.sin_port));

  packet_t packet_buffer;
  packet_t* packet = &packet_buffer;
  struct sockaddr_in addr;

  // Listen for incoming packets
  while (running) {
    switch (packet_recv(socket_fd, packet, config.key, config.strict_version, &addr)) {
      case NETDISK_PACKET_STATUS_INTERRUPT:
        log_debug("packet_recv SIGINT...");
      case NETDISK_PACKET_STATUS_NO_PACKET:
        break;
      case NETDISK_PACKET_STATUS_OK:
        process_packet(packet, &addr);
        continue;
      case NETDISK_PACKET_STATUS_BAD_KEY:
        log_warn("Packet with bad magic number from %s:%d (incorrect encryption key?)", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        break;
      case NETDISK_PACKET_STATUS_BAD_LENGTH:
        log_warn("Packet incorrect length from %s:%d", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        break;
      case NETDISK_PACKET_STATUS_BAD_VERSION:
        log_warn("Packet with incompatible version from %s:%d (%d.%d.%d)", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), packet->fields.version.major,
                 packet->fields.version.minor, packet->fields.version.patch);
        break;
      default:
        log_error("Unknown error while processing packet from %s:%d", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        break;
    }
  }

  // Close the socket
  log_debug("Close UDP socket...");
  packet_destroy_socket(socket_fd);

  // Close the file/device
  log_debug("Close file...");
  close(disk_fd);

  // Close the random source
  log_debug("Close RNG...");
  random_shutdown();

  log_info("Shutdown");

  return 0;
}

void process_packet(packet_t* packet, struct sockaddr_in* addr) {
  // log_debug("Received packet from %s:%d", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));

  packet_t reply_buffer;
  packet_t* reply = &reply_buffer;

  packet_init(reply);
  reply->fields.block_offset = packet->fields.block_offset;
  reply->fields.sequence = packet->fields.sequence;
  reply->fields.command = packet->fields.command;
  reply->fields.user_data = packet->fields.user_data;

  // TODO: Check timestamp and sequence

  // Switch on packet command
  switch (packet->fields.command) {
    case NETDISK_COMMAND_START:
      log_debug("NETDISK_COMMAND_START from %s:%d", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
      reply->fields.reply = NETDISK_REPLY_OK;
      if (packet_send(socket_fd, reply, config.key, addr) != NETDISK_PACKET_STATUS_OK) {
        log_error("packet_send failed");
      }
      break;

    case NETDISK_COMMAND_STOP:
      log_debug("NETDISK_COMMAND_STOP from %s:%d", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
      reply->fields.reply = NETDISK_REPLY_OK;
      if (packet_send(socket_fd, reply, config.key, addr) != NETDISK_PACKET_STATUS_OK) {
        log_error("packet_send failed");
        break;
      }
      break;

    case NETDISK_COMMAND_READ:
      log_debug("NETDISK_COMMAND_READ from %s:%d, block_offset %llu, user_data %llu", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port), packet->fields.block_offset, packet->fields.user_data);

      if (config.max_blocks != 0 && config.max_blocks < packet->fields.block_offset) {
      // Out of Range?
        log_warn("Packet NETDISK_COMMAND_READ from %s:%d block_offset out of range (%d)", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port),
                 packet->fields.block_offset);
        reply->fields.reply = NETDISK_REPLY_OUT_OF_RANGE;
        if (packet_send(socket_fd, reply, config.key, addr) != NETDISK_PACKET_STATUS_OK) {
          log_error("packet_send failed");
        }
      } else if (lseek(disk_fd, packet->fields.block_offset << NETDISK_BLOCK_SHIFT, SEEK_SET) != packet->fields.block_offset << NETDISK_BLOCK_SHIFT) {
        // lseek Fails?
        reply->fields.reply = NETDISK_REPLY_ERROR;
        if (packet_send(socket_fd, reply, config.key, addr) != NETDISK_PACKET_STATUS_OK) {
          log_error("packet_send failed");
        }
        log_error("lseek failed");
      } else if (read(disk_fd, reply->fields.payload, NETDISK_BLOCK_SIZE) != NETDISK_BLOCK_SIZE) {
        // read fails?
        reply->fields.reply = NETDISK_REPLY_ERROR;
        if (packet_send(socket_fd, reply, config.key, addr) != NETDISK_PACKET_STATUS_OK) {
          log_error("packet_send failed");
        }
        log_error("read failed");
      } else {
        // Send OK
        reply->fields.reply = NETDISK_REPLY_READ_OK;
        if (packet_send(socket_fd, reply, config.key, addr) != NETDISK_PACKET_STATUS_OK) {
          log_error("packet_send failed");
        }
      }
      break;

    case NETDISK_COMMAND_WRITE:
      log_debug("NETDISK_COMMAND_WRITE from %s:%d, block_offset %llu, user_data %llu", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port), packet->fields.block_offset, packet->fields.user_data);
      
      if (config.read_only) {
        // Read Only?
        log_warn("Packet NETDISK_COMMAND_WRITE from %s:%d while in read only mode", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
        reply->fields.reply = NETDISK_REPLY_READ_ONLY;
        if (packet_send(socket_fd, reply, config.key, addr) != NETDISK_PACKET_STATUS_OK) {
          log_error("packet_send failed");
        }
      } else if (config.max_blocks != 0 && config.max_blocks < packet->fields.block_offset) {
        // Out of Range?
        log_warn("Packet NETDISK_COMMAND_WRITE from %s:%d block_offset out of range (%d)", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port),
                 packet->fields.block_offset);
        reply->fields.reply = NETDISK_REPLY_OUT_OF_RANGE;
        if (packet_send(socket_fd, reply, config.key, addr) != NETDISK_PACKET_STATUS_OK) {
          log_error("packet_send failed");
        }
      } else if (lseek(disk_fd, packet->fields.block_offset << NETDISK_BLOCK_SHIFT, SEEK_SET) != packet->fields.block_offset << NETDISK_BLOCK_SHIFT) {
        // lseek fails?
        reply->fields.reply = NETDISK_REPLY_ERROR;
        if (packet_send(socket_fd, reply, config.key, addr) != NETDISK_PACKET_STATUS_OK) {
          log_error("packet_send failed");
        }
      } else if (write(disk_fd, packet->fields.payload, NETDISK_BLOCK_SIZE) != NETDISK_BLOCK_SIZE) {
        // write fails?
        reply->fields.reply = NETDISK_REPLY_ERROR;
        if (packet_send(socket_fd, reply, config.key, addr) != NETDISK_PACKET_STATUS_OK) {
          log_error("packet_send failed");
        }
        log_error("write failed");
      } else {
        // All is good
        reply->fields.reply = NETDISK_REPLY_WRITE_OK;
        if (packet_send(socket_fd, reply, config.key, addr) != NETDISK_PACKET_STATUS_OK) {
          log_error("packet_send failed");
        }
      }
      break;
      
    default:
      log_warn("Unknown Command from %s:%d (%d)", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port), packet->fields.command);
  }
}

void signal_stop(int signum) {
  if (!stopping) {
    running = false;
    stopping = true;
  }
}
