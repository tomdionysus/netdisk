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

  log_debug("Creating socket...");

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
  log_info("netdiskd listening on %s:%d", inet_ntoa(config.addr.sin_addr), ntohs(config.addr.sin_port));

  // Close the socket
  log_debug("Close socket...");
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

void signal_stop(int signum) {
  if (!stopping) {
    running = false;
    stopping = true;
  }
}
