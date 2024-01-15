//
// netdisk_testclient main
//
// Copyright (C) Tom Cully 2024
// Licensed under the MIT License (see LICENSE in root of project)
//
#include "main.h"

volatile bool running = true;
volatile bool stopping = false;
netdisk_testclient_config_t config;
int socket_fd;

int main(int argc, char* argv[]) {
  if (!parse_config(argc, argv, &config)) {
    exit(EXIT_FAILURE);
  }

  log_set_level(config.log_level);

  log_raw("-------------------------");
  log_raw("netdisk_testclient v%d.%d.%d", NETDISK_VERSION_MAJOR, NETDISK_VERSION_MINOR, NETDISK_VERSION_PATCH);
  log_raw("-------------------------");

  if (config.log_level == LOG_LEVEL_DEBUG) dump_config(&config);

  struct sockaddr_in client_addr;
  char buffer[NETDISK_MAX_PACKET_SIZE];
  ssize_t recv_len;
  struct timeval tv;

  log_debug("Creating UDP socket...");
  memset(&client_addr, 0, sizeof(client_addr));
  client_addr.sin_addr.s_addr = INADDR_ANY;
  client_addr.sin_port = 0;
  client_addr.sin_family = AF_INET;

  switch (packet_create_socket(&socket_fd, &client_addr)) {
    case NETDISK_PACKET_SOCKET_OK:
      break;
    case NETDISK_PACKET_SOCKET_CREATE_FAILED:
      log_error("Socket creation failed");
      exit(EXIT_FAILURE);
      break;
    case NETDISK_PACKET_SOCKET_BIND_FAILED:
      log_error("Binding to address %s:%d failed", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
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

  // Setup CTRL-C (SIGINT) quit
  log_debug("Register SIGINT...");
  signal(SIGINT, signal_stop);

  // Log Started
  log_info("netdisk_testclient listening on UDP Port %d", ntohs(client_addr.sin_port));

  // Send Start
  packet_t packet_buffer;
  packet_t* packet = &packet_buffer;
  struct sockaddr_in addr;

  packet_init(packet);
  packet->fields.command = NETDISK_COMMAND_START;

  log_info("Sending NETDISK_COMMAND_START to %s:%d", inet_ntoa(config.addr.sin_addr), ntohs(config.addr.sin_port));
  if (packet_send(socket_fd, packet, config.key, &config.addr) != NETDISK_PACKET_STATUS_OK) {
    log_error("packet_send failed");
  }

  // Listen for incoming packets
  while (running) {
    switch (packet_recv(socket_fd, packet, config.key, false, &addr)) {
      case NETDISK_PACKET_STATUS_INTERRUPT:
        log_debug("packet_recv SIGINT...");
      case NETDISK_PACKET_STATUS_NO_PACKET:
        break;
      case NETDISK_PACKET_STATUS_OK:
        process_packet(packet, &addr);
        break;
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

  // Close the random source
  log_debug("Close RNG...");
  random_shutdown();

  log_info("Shutdown");

  return 0;
}

void process_packet(packet_t* packet, struct sockaddr_in* addr) {
  log_debug("Received packet from %s:%d", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));

  packet_t reply_buffer;
  packet_t* reply = &reply_buffer;

  packet_init(reply);
  reply->fields.block_offset = packet->fields.block_offset;
  reply->fields.sequence = packet->fields.sequence;
  reply->fields.user_data = packet->fields.user_data;

  // TODO: Check timestamp and sequence

  // Switch on packet reply
  switch (packet->fields.reply) {
    case NETDISK_REPLY_OK:
      log_info("NETDISK_REPLY_OK from %s:%d", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
      break;
    default:
      log_warn("Unknown Reply from %s:%d (%d)", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port), packet->fields.command);
  }
}

void signal_stop(int signum) {
  if (!stopping) {
    running = false;
    stopping = true;
  } else {
    exit(1);
  }
}
