//
// netdiskd main
//
// Copyright (C) Tom Cully 2024
// Licensed under the MIT License (see LICENSE in root of project)
//
#include "main.h"

netdiskd_config_t config;

volatile bool running = true;
volatile bool stopping = false;

int main(int argc, char* argv[]) {
  int socket_fd;
  int disk_fd;

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

  switch (packet_create_server_socket(&socket_fd, &(config.addr))) {
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

  int addrlen = sizeof(struct sockaddr_in);
  fd_set readfds;
  int max_sd;

  session_t* new_session = NULL;

  while (running) {
    // Initialise new session (waiting)
    if (new_session == NULL) {
      new_session = (session_t*)calloc(sizeof(session_t), 1);
    }

    // Clear the socket set
    FD_ZERO(&readfds);

    // Add the server socket to the set
    FD_SET(socket_fd, &readfds);
    max_sd = socket_fd;

    // Wait for an activity on one of the sockets, timeout is NULL, so wait indefinitely
    int activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);

    // Handle SIGINT (close server)
    if (errno == EINTR) {
      log_debug("EINTR received");
      running = false;
      continue;
    }

    if (activity < 0) {
      log_error("Select Error");
      running = false;
      continue;
    }

    // Check if it was for the server socket, meaning an incoming connection
    if (FD_ISSET(socket_fd, &readfds)) {
      if ((new_session->socket_fd = accept(socket_fd, (struct sockaddr*)&(new_session->remote_addr), (socklen_t*)&addrlen)) < 0) {
        log_error("Accept Error");
      }

      if (pthread_create(&new_session->thread_id, NULL, handle_connection, new_session) != 0) {
        log_error("Cannot create handler thread");
      } else {
        new_session = NULL;
      }
    }
  }

  // Free the waiting session info
  if (new_session != NULL) free(new_session);

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

void* handle_connection(void* arg) {
  volatile bool thread_running = true;

  session_t* session = (session_t*)arg;
  log_info("Connected %s:%d", inet_ntoa(session->remote_addr.sin_addr), ntohs(session->remote_addr.sin_port));

  // Allocate session buffer.
  session->buffer = malloc(NETDISK_MAX_PACKET_SIZE);

  ssize_t recvlen;
  packet_handshake_t* packet;
  packet_header_t* header;

  while (thread_running) {
    switch (session->state) {
      case NETDISK_SESSION_STATE_INITIAL:
        // Initial state.
        random_get(session->buffer, NETDISK_KEY_SIZE);
        // Setup TX AES Context
        AES_init_ctx_iv(&session->tx_aes_context, config.key, session->buffer);
        // Send IV
        send(session->socket_fd, session->buffer, NETDISK_KEY_SIZE, 0);
        // Set State
        session->state = NETDISK_SESSION_STATE_IV;
        log_debug("Client is NETDISK_SESSION_STATE_IV");
        break;
      case NETDISK_SESSION_STATE_IV:
        // Wait for other side of IV
        recvlen = recv_exact_with_timeout(session->socket_fd, session->buffer, NETDISK_KEY_SIZE, 5000);
        if (recvlen == NETDISK_KEY_SIZE) {
          // Setup RX AES Context
          AES_init_ctx_iv(&session->rx_aes_context, config.key, session->buffer);
          // Init Handshake, Create NodeID
          packet = (packet_handshake_t*)session->buffer;
          packet_handshake_init(packet);
          random_get((uint8_t*)&packet->node_id, sizeof(packet->node_id));
          // Encrypt
          AES_CBC_encrypt_buffer(&session->tx_aes_context, session->buffer, sizeof(packet_handshake_t));
          // Send Handshake
          ssize_t bytes_sent = send(session->socket_fd, session->buffer, sizeof(packet_handshake_t), 0);
          if (bytes_sent < sizeof(packet_handshake_t)) {
            // Handle the error case
            log_error("send failed, closing connection");
            thread_running = false;
          }
          // Set State
          session->state = NETDISK_SESSION_STATE_HANDSHAKE;
          log_debug("Client is NETDISK_SESSION_STATE_HANDSHAKE");
        } else if (recvlen == -999) {
          log_warn("Timeout, closing connection");
          thread_running = false;
        } else {
          log_warn("Error, closing connection");
          thread_running = false;
        }
        break;
      case NETDISK_SESSION_STATE_HANDSHAKE:
        // Wait for handshake packet
        recvlen = recv_exact_with_timeout(session->socket_fd, session->buffer, sizeof(packet_handshake_t), 5000);
        if (recvlen == sizeof(packet_handshake_t)) {
          // Decrypt
          AES_CBC_decrypt_buffer(&session->rx_aes_context, session->buffer, recvlen);
          packet = (packet_handshake_t*)session->buffer;
          // Check Magic number
          if (!packet_magic_check(packet)) {
            log_warn("Bad magic number from %s:%d, disconnecting", inet_ntoa(session->remote_addr.sin_addr), ntohs(session->remote_addr.sin_port));
            thread_running = false;
            break;
          }
          // Check Version
          if (!packet_version_check(packet, false)) {
            log_warn("Incompatible version from %s:%d, disconnecting", inet_ntoa(session->remote_addr.sin_addr), ntohs(session->remote_addr.sin_port));
            thread_running = false;
            break;
          }
          // Get NodeID
          session->node_id = packet->node_id;
          // Set state ready
          log_debug("Client is NETDISK_SESSION_STATE_READY");
          session->state = NETDISK_SESSION_STATE_READY;
        } else if (recvlen == -999) {
          log_warn("Timeout");
          thread_running = false;
        } else {
          thread_running = false;
        }
        break;
      case NETDISK_SESSION_STATE_READY:
        // Read a header, then a packet of that length
        recvlen = recv_exact_with_timeout(session->socket_fd, session->buffer, sizeof(packet_header_t), 10000);
        if (recvlen == sizeof(packet_header_t)) {
          // Decrypt
          AES_CBC_decrypt_buffer(&session->rx_aes_context, session->buffer, recvlen);
          header = (packet_header_t*)session->buffer;
          // Check we have enough buffer
          if (header->length > NETDISK_MAX_PACKET_SIZE) {
            log_warn("Packet too large (%d bytes, limit %d)", header->length, NETDISK_MAX_PACKET_SIZE);
            thread_running = false;
            break;
          }
          // If there's more data, receive it
          if (header->length > 0) {
            if (recv_exact_with_timeout(session->socket_fd, session->buffer + sizeof(packet_header_t), sizeof(packet_header_t), 10000) != header->length) {
              log_warn("Tiemout receiving Packet data (%d bytes)", header->length);
              thread_running = false;
              break;
            }
            // And Decrypt it
            AES_CBC_decrypt_buffer(&session->rx_aes_context, session->buffer + sizeof(packet_header_t), header->length);
          }
          // Process the packet, stop if return true
          if (process_packet(session, header, session->buffer + sizeof(packet_header_t))) {
            thread_running = false;
            break;
          }
        } else if (recvlen == -999) {
          // Do Nothing
        } else {
          thread_running = false;
        }
        break;
    }
  }

  // Close socket
  log_info("Closing Connection %s:%d", inet_ntoa(session->remote_addr.sin_addr), ntohs(session->remote_addr.sin_port));
  close(session->socket_fd);

  // Free Session Buffer
  free(session->buffer);

  // Free Session
  free(session);

  return NULL;
}

bool process_packet(session_t* session, packet_header_t* header, uint8_t* data) { return false; }

void signal_stop(int signum) {
  if (!stopping) {
    running = false;
    stopping = true;
  }
}
