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
session_t session_raw;
session_t *session = &session_raw;

pthread_t send_thread_id = NULL;

void* run_send_thread(void* arg) {
  while (running) {
    packet_header_t *header = malloc(NETDISK_MAX_PACKET_SIZE);

    if((rand() % 2) != 0) {
      header->operation = NETDISK_COMMAND_READ;
      header->block_id = rand() % 128;
      header->length = 0;
    } else {
      header->operation = NETDISK_COMMAND_WRITE;
      header->block_id = rand() % 128;
      header->length = NETDISK_BLOCK_SIZE;
    }

    uint32_t olen = sizeof(packet_header_t) + header->length;
        AES_CBC_encrypt_buffer(&session->tx_aes_context, (uint8_t*)header, olen);

        // Send Command
        ssize_t bytes_sent = packet_send(session->socket_fd, (uint8_t*)header,olen);
        if (bytes_sent < sizeof(packet_handshake_t)) {
            // Handle the error case
            log_error("send failed");
        }

        free(header);
    sleep(1); // Wait for 1 second
  }
  return NULL;
}

int main(int argc, char* argv[]) {
  if (!parse_config(argc, argv, &config)) {
    exit(EXIT_FAILURE);
  }

  log_set_level(config.log_level);

  log_raw("-------------------------");
  log_raw("netdisk_testclient v%d.%d.%d", NETDISK_VERSION_MAJOR, NETDISK_VERSION_MINOR, NETDISK_VERSION_PATCH);
  log_raw("-------------------------");

  if (config.log_level == LOG_LEVEL_DEBUG) dump_config(&config);

  uint8_t buffer[NETDISK_MAX_PACKET_SIZE];
  ssize_t recvlen;

  log_debug("Creating socket...");

  switch (packet_create_client_socket(&session->socket_fd, &config.addr)) {
    case NETDISK_PACKET_SOCKET_OK:
      break;
    case NETDISK_PACKET_SOCKET_CREATE_FAILED:
      log_error("Socket creation failed");
      exit(EXIT_FAILURE);
      break;
    case NETDISK_PACKET_SOCKET_CONNECT_FAILED:
      log_error("Connecting to address %s:%d failed", inet_ntoa(config.addr.sin_addr), ntohs(config.addr.sin_port));
      exit(EXIT_FAILURE);
      break;
  }

  // Start the random number generator
  log_debug("Initialise RNG...");
  if (!random_init()) {
    log_error("Failed to initialise cryptographic random source");
    close(session->socket_fd);
    exit(EXIT_FAILURE);
  }

  // Setup CTRL-C (SIGINT) quit
  log_debug("Register SIGINT...");
  signal(SIGINT, signal_stop);

  packet_handshake_t* packet;
  packet_header_t* header;

  session->state = NETDISK_SESSION_STATE_INITIAL;
  log_debug("Client is NETDISK_SESSION_STATE_INITIAL");

  session->buffer = malloc(NETDISK_MAX_PACKET_SIZE);

  ssize_t bytes_sent;

  while (running) {
    switch (session->state) {
      case NETDISK_SESSION_STATE_INITIAL:
        // Initial state.
        random_get(session->buffer, NETDISK_KEY_SIZE);
        // Setup TX AES Context
        AES_init_ctx_iv(&session->tx_aes_context, config.key, session->buffer);
        // Send IV
         bytes_sent = packet_send(session->socket_fd, session->buffer, NETDISK_KEY_SIZE);
          if (bytes_sent < NETDISK_KEY_SIZE) {
              // Handle the error case
              log_error("send failed, closing connection");
              running = false;
          }
        // Set State
        session->state = NETDISK_SESSION_STATE_IV;
        log_debug("Client is NETDISK_SESSION_STATE_IV");
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
          // Create a random node ID
          random_get((uint8_t*)&packet->node_id, sizeof(packet->node_id));
          // Encrypt
          AES_CBC_encrypt_buffer(&session->tx_aes_context, session->buffer, sizeof(packet_handshake_t));
          // Send Handshake
          bytes_sent = packet_send(session->socket_fd, session->buffer, sizeof(packet_handshake_t));
          if (bytes_sent < sizeof(packet_handshake_t)) {
              // Handle the error case
              log_error("send failed, closing connection");
              running = false;
          }
          // Set State
          session->state = NETDISK_SESSION_STATE_HANDSHAKE;
          log_debug("Client is NETDISK_SESSION_STATE_HANDSHAKE");
        } else if (recvlen == -999) {
          log_warn("Timeout, closing connection");
          running = false;
        } else {
          log_warn("Error, closing connection");
          running = false;
        }
        break;
      case NETDISK_SESSION_STATE_HANDSHAKE:

        if(send_thread_id==NULL) {
          if (pthread_create(&send_thread_id, NULL, run_send_thread, NULL) != 0) {
              log_error("pthread_create");
              running = false;
          }
        }

        // Wait for handshake packet
        recvlen = packet_recv(session->socket_fd, session->buffer, sizeof(packet_handshake_t), 5000);
        if (recvlen == sizeof(packet_handshake_t)) {
          // Decrypt
          AES_CBC_decrypt_buffer(&session->rx_aes_context, session->buffer, recvlen);
          // Check Magic number
          packet = (packet_handshake_t*)session->buffer;
          if (!packet_magic_check(packet)) {
            log_warn("Bad magic number from %s:%d, disconnecting", inet_ntoa(session->remote_addr.sin_addr), ntohs(session->remote_addr.sin_port));
            running = false;
            break;
          }
          // Check Version
          if (!packet_version_check(packet, false)) {
            log_warn("Incompatible version from %s:%d, disconnecting", inet_ntoa(session->remote_addr.sin_addr), ntohs(session->remote_addr.sin_port));
            running = false;
            break;
          }
          // Get NodeID
          session->node_id = packet->node_id;
          // Set state ready
          log_debug("Client is NETDISK_SESSION_STATE_READY");
          session->state = NETDISK_SESSION_STATE_READY;
        } else if (recvlen == -999) {
          log_warn("Timeout, closing connection");
          running = false;
        } else {
          running = false;
        }
        break;
      case NETDISK_SESSION_STATE_READY:
        // Read a header, then a packet of that length
        recvlen = packet_recv(session->socket_fd, session->buffer, sizeof(packet_header_t), 1000);
        if (recvlen > 0) {
          // Decrypt
          AES_CBC_decrypt_buffer(&session->rx_aes_context, session->buffer, recvlen);
          header = (packet_header_t*)session->buffer;

          // Check we have enough buffer
          if (header->length > NETDISK_MAX_PACKET_SIZE) {
            log_warn("Packet too long (%d bytes, limit %d)", header->length, NETDISK_MAX_PACKET_SIZE);
            running = false;
            break;
          }
          // If there's more data, receive it
          if (header->length > 0) {
            if (packet_recv(session->socket_fd, (uint8_t*)session->buffer + sizeof(packet_header_t), header->length, 1000) != header->length) {
              log_warn("Timeout receiving packet data (%d bytes)", header->length);
              running = false;
              break;
            }
            // And Decrypt it
            AES_CBC_decrypt_buffer(&session->rx_aes_context, (uint8_t*)session->buffer + sizeof(packet_header_t), header->length);
          }
          // Process the packet, stop if return true
          if (process_packet(session, header, (uint8_t*)session->buffer + sizeof(packet_header_t))) {
            running = false;
            break;
          }
        } else if (recvlen == -999) {
          // Do Nothing
        } else {
          running = false;
        }
        break;
    }
  }

  running = false;

  if(send_thread_id!=NULL) {
    // Optionally join the thread
    pthread_join(send_thread_id, NULL);
  }

  // Close the socket
  log_debug("Close socket...");
  packet_destroy_socket(session->socket_fd);
  
  free(session->buffer);

  // Close the random source
  log_debug("Close RNG...");
  random_shutdown();

  log_info("Shutdown");

  return 0;
}

bool process_packet(session_t* session, packet_header_t* header, uint8_t* data) {

  log_debug("process_packet (%d bytes)", header->length);

  return false;
}

void signal_stop(int signum) {
  if (!stopping) {
    running = false;
    stopping = true;
  } else {
    log_info("Force Exit");
    exit(1);
  }
}
