//
// libnetdisk random functions
//
// Copyright (C) Tom Cully 2024
// Licensed under the MIT License (see LICENSE in root of project)
//
#include "random.h"

int random_fd;

bool random_init() {
  random_fd = open("/dev/urandom", O_RDONLY);
  return (random_fd != -1);
};

bool random_get(unsigned char *buffer, size_t num_bytes) {
  if (buffer == NULL) {
    return false;
  }

#ifdef __APPLE__
  // macOS implementation
  arc4random_buf(buffer, num_bytes);
  return true;
#else
  // Linux implementation
  size_t read_bytes = 0;
  size_t total_read = 0;
  while (total_read < num_bytes) {
    read_bytes = read(random_fd, buffer + total_read, num_bytes - total_read);
    if (read_bytes <= 0) {
      return false;
    }
    total_read += read_bytes;
  }

  return true;
#endif
}

bool random_shutdown() {
  close(random_fd);
  random_fd = 0;
  return true;
}
