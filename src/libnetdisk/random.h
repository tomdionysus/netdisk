//
// libnetdisk random functions
//
// Copyright (C) Tom Cully 2024
// Licensed under the MIT License (see LICENSE in root of project)
//
#ifndef NETDISK_RANDOM
#define NETDISK_RANDOM

#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

bool random_init();
bool random_get(unsigned char *buffer, size_t num_bytes);
bool random_shutdown();

#endif
