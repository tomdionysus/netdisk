//
// netdiskd config functions
//
// Copyright (C) Tom Cully 2024
// Licensed under the MIT License (see LICENSE in root of project)
//
#include "config.h"

bool parse_config(int argc, char *argv[], netdisk_testclient_config_t *config) {
  // Defaults
  memset(config, 0, sizeof(netdisk_testclient_config_t));

  config->log_level = LOG_LEVEL_ERROR;
  config->addr.sin_family = AF_INET;
  config->addr.sin_addr.s_addr = INADDR_ANY;
  config->addr.sin_port = htons(NETDISK_DEFAULT_PORT);

  // Parse arguments
  bool ok = true;
  bool key_given = false;

  for (int i = 1; i < argc; i++) {
    if (strncmp(argv[i], "--port=", 7) == 0) {
      config->addr.sin_port = htons(atoi(argv[i] + 7));
    } else if (strncmp(argv[i], "--address=", 10) == 0) {
      if (inet_pton(AF_INET, argv[i] + 10, &(config->addr.sin_addr)) != 1) {
        log_error("--address must be a valid IPv4 address");
        ok = false;
      }
    } else if (strncmp(argv[i], "--log_level=", 12) == 0) {
      config->log_level = parse_log_level(argv[i] + 12);
      if (config->log_level == LOG_LEVEL_UNKNOWN) {
        log_error("--log_level must be DEBUG, INFO, WARN or ERROR.");
        ok = false;
      }
    } else if (strncmp(argv[i], "--key=", 6) == 0) {
      if (strlen(argv[i] + 6) != 64) {  // Check if the string has 64 characters (256 bits)
        log_error("--key must be 256 bits long in hexadecimal format.");
        ok = false;
      }
      parse_key(argv[i] + 6, config->key);
      key_given = true;
    } else if (strncmp(argv[i], "--help", 6) == 0) {
      printf("netdiskd v%d.%d.%d\n\n", NETDISK_VERSION_MAJOR, NETDISK_VERSION_MINOR, NETDISK_VERSION_PATCH);
      printf("Usage: %s --key=<key> ---address=<address> [options]\n\n", argv[0]);
      printf(" --port=<port>                  - UDP server port\n");
      printf(" --address=<address>            - IPv4 server address\n");
      printf(" --key=<key>                    - 256 bit AES key in hexadecimal\n");
      printf(" --read_only=[true,false]>      - If true, disable writes\n\n");
      exit(0);
    } else {
      log_error("Unknown option %s", argv[i]);
      ok = false;
    }
  }

  ok &= key_given;

  if (!key_given) {
    log_error("--key must be specified");
  }

  return ok;
}

void dump_config(netdisk_testclient_config_t *config) {
  char hexbuffer[65];
  buffer_to_hex_string(config->key, NETDISK_KEY_SIZE, hexbuffer, (NETDISK_KEY_SIZE * 2) + 1);
  log_debug("config: address = %s", inet_ntoa(config->addr.sin_addr));
  log_debug("config: port = %d", ntohs(config->addr.sin_port));
  log_debug("config: key = %s", hexbuffer);
}

void parse_key(const char *hex_str, uint8_t *key) {
  for (int i = 0; i < NETDISK_KEY_SIZE; ++i) {
    sscanf(hex_str + 2 * i, "%2hhx", &key[i]);
  }
}

void buffer_to_hex_string(const uint8_t *buffer, size_t buffer_size, char *hex_string, size_t hex_string_size) {
  if (buffer == NULL || hex_string == NULL || hex_string_size < 2 * buffer_size + 1) {
    // Handle error: invalid parameters
    log_error("buffer_to_hex_string: bad key supplied");
    return;
  }

  for (size_t i = 0; i < buffer_size; ++i) {
    snprintf(hex_string + 2 * i, hex_string_size - 2 * i, "%02x", buffer[i]);
  }
  hex_string[2 * buffer_size] = '\0';  // Null-terminate the string
}