//
// netdiskd config functions
//
// Copyright (C) Tom Cully 2024
// Licensed under the MIT License (see LICENSE in root of project)
//
#ifndef NETDISK_TESTCLIENT_CONFIG
#define NETDISK_TESTCLIENT_CONFIG

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shared/packet.h"
#include "logger.h"

typedef struct {
  struct sockaddr_in addr;
  log_level_t log_level;
  uint8_t key[NETDISK_KEY_SIZE];
} netdisk_testclient_config_t;

bool parse_config(int argc, char *argv[], netdisk_testclient_config_t *config);
void dump_config(netdisk_testclient_config_t *config);
void parse_key(const char *hex_str, uint8_t *key);
void buffer_to_hex_string(const uint8_t *buffer, size_t buffer_size, char *hex_string, size_t hex_string_size);

#endif