//
// netdiskd main
//
// Copyright (C) Tom Cully 2024
// Licensed under the MIT License (see LICENSE in root of project)
//
#include <errno.h>

#include "main.h"

netdiskd_config_t config;

volatile bool running = true;
volatile bool stopping = false;
FILE* disk_fd;

int main(int argc, char* argv[]) {
  int server_socket_fd;

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

  switch (packet_create_server_socket(&server_socket_fd, &(config.addr))) {
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
    close(server_socket_fd);
    exit(EXIT_FAILURE);
  }

  // Open the file/device
  log_debug("Open file or device...");
  if ((disk_fd = fopen(config.file, config.read_only ? "r" : "r+")) == NULL) {
    log_error("Failed to open file/device %s", config.file);
    close(server_socket_fd);
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
    close(server_socket_fd);
    random_shutdown();
    exit(EXIT_FAILURE);
  }

  // Log Started
  log_info("netdiskd listening on %s:%d", inet_ntoa(config.addr.sin_addr), ntohs(config.addr.sin_port));

  int addrlen = sizeof(struct sockaddr_in);
  fd_set readfds;
  int max_sd;
  int socket_fd;
  struct sockaddr_in remote_addr;

  session_t* new_session = NULL;

  while (running) {
    // Clear the socket set
    FD_ZERO(&readfds);

    // Add the server socket to the set
    FD_SET(server_socket_fd, &readfds);
    max_sd = server_socket_fd;

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
    if (FD_ISSET(server_socket_fd, &readfds)) {
      if ((socket_fd = accept(server_socket_fd, (struct sockaddr*)&(remote_addr), (socklen_t*)&addrlen)) < 0) {
        log_error("Accept Error %d");
        continue;
      }

      new_session = session_create(socket_fd, remote_addr, handle_connection);
      if (!new_session) {
        log_error("Cannot create session");
      } else {
        new_session = NULL;
      }
    }
  }

  // Close the socket
  log_debug("Close socket...");
  packet_destroy_socket(server_socket_fd);

  // Close the file/device
  log_debug("Close file...");
  fclose(disk_fd);

  // Close the random source
  log_debug("Close RNG...");
  random_shutdown();

  log_info("Shutdown");

  return 0;
}

void* handle_connection(void* arg) {
  session_t* session = (session_t*)arg;
  bool thread_running = true;

  ssize_t recvlen;
  packet_handshake_t* packet;
  packet_header_t* header;

  log_info("(%s) Connected", session->remote_addr_str);

  while (running && thread_running) {
    switch (session->state) {
      case NETDISK_SESSION_STATE_INITIAL:
        // Initial state.
        random_get(session->buffer, NETDISK_KEY_SIZE);
        // Setup TX AES Context
        AES_init_ctx_iv(&session->tx_aes_context, config.key, session->buffer);
        // Send IV
        packet_send(session->socket_fd, session->buffer, NETDISK_KEY_SIZE);
        // Set State
        session->state = NETDISK_SESSION_STATE_IV;
        log_debug("(%s) NETDISK_SESSION_STATE_IV", session->remote_addr_str);
        break;
      case NETDISK_SESSION_STATE_IV:
        // Wait for other side of IV
        recvlen = packet_recv(session->socket_fd, session->buffer, NETDISK_KEY_SIZE, 5000);
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
          ssize_t bytes_sent = packet_send(session->socket_fd, session->buffer, sizeof(packet_handshake_t));
          if (bytes_sent < sizeof(packet_handshake_t)) {
            // Handle the error case
            log_error("(%s) Send failed", session->remote_addr_str);
            thread_running = false;
          }
          // Set State
          session->state = NETDISK_SESSION_STATE_HANDSHAKE;
          log_debug("(%s) NETDISK_SESSION_STATE_HANDSHAKE", session->remote_addr_str);
        } else if (recvlen == -999) {
          log_warn("(%s) Timeout", session->remote_addr_str);
          thread_running = false;
        } else {
          log_warn("(%s) Error", session->remote_addr_str);
          thread_running = false;
        }
        break;
      case NETDISK_SESSION_STATE_HANDSHAKE:
        // Wait for handshake packet
        recvlen = packet_recv(session->socket_fd, session->buffer, sizeof(packet_handshake_t), 5000);
        if (recvlen == sizeof(packet_handshake_t)) {
          // Decrypt
          AES_CBC_decrypt_buffer(&session->rx_aes_context, session->buffer, recvlen);
          packet = (packet_handshake_t*)session->buffer;
          // Check Magic number
          if (!packet_magic_check(packet)) {
            log_warn("(%s) Bad magic number", session->remote_addr_str);
            thread_running = false;
            break;
          }
          // Check Version
          if (!packet_version_check(packet, false)) {
            log_warn("(%s) Incompatible version", session->remote_addr_str);
            thread_running = false;
            break;
          }
          // Get NodeID
          session->node_id = packet->node_id;
          // Set state ready
          log_debug("(%s) NETDISK_SESSION_STATE_READY", session->remote_addr_str);
          session->state = NETDISK_SESSION_STATE_READY;
        } else if (recvlen == -999) {
          log_warn("(%s) Timeout", session->remote_addr_str);
          thread_running = false;
        } else {
          log_warn("(%s) Unknown Error", session->remote_addr_str);
          thread_running = false;
        }
        break;
      case NETDISK_SESSION_STATE_READY:
        // Read a header, then a packet of that length
        recvlen = packet_recv(session->socket_fd, session->buffer, sizeof(packet_header_t), 1000);
        if (recvlen > 0) {
          // Decrypt
          AES_CBC_decrypt_buffer(&session->rx_aes_context, session->buffer, sizeof(packet_header_t));
          header = (packet_header_t*)session->buffer;
          // Check we have enough buffer
          if (header->length > NETDISK_MAX_PACKET_SIZE) {
            log_warn("(%s) Packet too large (%d bytes, limit %d)", session->remote_addr_str, header->length, NETDISK_MAX_PACKET_SIZE);
            thread_running = false;
            break;
          }
          // If there's more data, receive it
          if (header->length > 0) {
            if (packet_recv(session->socket_fd, (uint8_t*)session->buffer + sizeof(packet_header_t), header->length, 1000) != header->length) {
              log_warn("(%s) Timeout Packet data (%d bytes)", session->remote_addr_str, header->length);
              thread_running = false;
              break;
            }
            // And Decrypt it
            AES_CBC_decrypt_buffer(&session->rx_aes_context, (uint8_t*)session->buffer + sizeof(packet_header_t), header->length);
          }

          // Process the packet
          process_packet(session, header, (uint8_t*)session->buffer + sizeof(packet_header_t));

        } else if (recvlen == -999) {
          // Do Nothing, timeout in normal operation
        } else if (recvlen == 0) {
          // Connection terminated
          thread_running = false;
          log_info("(%s) Remotely Closed", session->remote_addr_str);
        } else {
          log_warn("(%s) Unknown Error %d", session->remote_addr_str, recvlen);
          thread_running = false;
        }
        break;
    }
  }

  // Close socket
  close(session->socket_fd);
  log_info("(%s) Disconnected", session->remote_addr_str);

  // Free Session
  session_release(session);

  return NULL;
}

bool process_packet(session_t* session, packet_header_t* header, uint8_t* data) {
  // Alloc Buffer
  packet_header_t* reply = (packet_header_t*)malloc(NETDISK_MAX_PACKET_SIZE);

  // Copy user info
  reply->block_id = header->block_id;
  reply->transaction_id = header->transaction_id;
  reply->user_data = header->user_data;
  reply->length = 0;

  ssize_t iolen;

  switch (header->operation) {
    case NETDISK_COMMAND_INFO:
      log_debug("(%s) NETDISK_COMMAND_INFO", session->remote_addr_str);
      reply->operation = NETDISK_REPLY_INFO;
      break;
    case NETDISK_COMMAND_READ:
      if (config.max_blocks != 0 && header->block_id > config.max_blocks) {
        log_error("(%s) NETDISK_COMMAND_READ Out of range (%d > %d)", session->remote_addr_str, header->block_id, config.max_blocks);
        reply->operation = NETDISK_REPLY_OUT_OF_RANGE;
      } else if ((iolen = fseek(disk_fd, header->block_id << NETDISK_BLOCK_SHIFT, SEEK_SET)) != 0) {
        log_error("(%s) NETDISK_COMMAND_READ Seek Error %d (pos %lu)", session->remote_addr_str, iolen, header->block_id << NETDISK_BLOCK_SHIFT);
        reply->operation = NETDISK_REPLY_OUT_OF_RANGE;
      } else {
        iolen = fread((uint8_t*)reply + sizeof(packet_header_t), header->block_length, 1, disk_fd);
        if (ferror(disk_fd)) {
          log_error("(%s) NETDISK_COMMAND_READ File Error %s (pos %lu, length %lu)", session->remote_addr_str, iolen, iolen,
                    header->block_id << NETDISK_BLOCK_SHIFT, header->block_length);
          reply->operation = NETDISK_REPLY_ERROR;
        } else {
          log_debug("(%s) NETDISK_COMMAND_READ Complete, Block %d Length %d", session->remote_addr_str, header->block_id, header->block_length);
          reply->operation = NETDISK_REPLY_OK;
          reply->length = header->block_length;
        }
      }
      break;
    case NETDISK_COMMAND_WRITE:
      if (config.read_only) {
        reply->operation = NETDISK_REPLY_READ_ONLY;
      } else if (config.max_blocks != 0 && header->block_id > config.max_blocks) {
        log_error("(%s) NETDISK_COMMAND_WRITE Out of range (%d > %d)", session->remote_addr_str, header->block_id, config.max_blocks);
        reply->operation = NETDISK_REPLY_OUT_OF_RANGE;
      } else if (fseek(disk_fd, header->block_id << NETDISK_BLOCK_SHIFT, SEEK_SET) != 0) {
        log_error("(%s) NETDISK_COMMAND_WRITE Seek Error %d (pos %lu)", session->remote_addr_str, iolen, header->block_id << NETDISK_BLOCK_SHIFT);
        reply->operation = NETDISK_REPLY_OUT_OF_RANGE;
      } else {
        iolen = fwrite(data, header->block_length, 1, disk_fd);
        if (ferror(disk_fd)) {
          log_error("(%s) NETDISK_COMMAND_WRITE File Error %d (pos %lu, length %lu)", session->remote_addr_str, iolen, header->block_id << NETDISK_BLOCK_SHIFT,
                    header->block_length);
          reply->operation = NETDISK_REPLY_ERROR;
        } else {
          log_debug("(%s) NETDISK_COMMAND_WRITE Complete, Block %d Length %d", session->remote_addr_str, header->block_id, header->block_length);
          reply->operation = NETDISK_REPLY_OK;
        }
      }
      break;
    default:
      log_warn("(%s) Unknown operation %d", session->remote_addr_str, header->operation);
      reply->operation = NETDISK_REPLY_UNKNOWN_COMMAND;
  }

  // Encrypt
  uint32_t olen = sizeof(packet_header_t) + reply->length;
  AES_CBC_encrypt_buffer(&session->tx_aes_context, (uint8_t*)reply, olen);

  // Send
  ssize_t sendlen = packet_send(session->socket_fd, (uint8_t*)reply, olen);
  if (sendlen != olen) {
    log_warn("(%s) Sending Failed %d", session->remote_addr_str, sendlen);
  };

  // Free Buffer
  free(reply);

  return false;
}

void signal_stop(int signum) {
  if (!stopping) {
    running = false;
    stopping = true;
  }
}
