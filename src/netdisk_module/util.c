//
// /dev/netdisk device driver
//
// Copyright (C) 2024 Tom Cully
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
//
// This is a heavily modified version of tiny-AES-c
// (https://github.com/kokke/tiny-AES-c)
//
#include "util.h"

int parse_key(const char *hex_str, u8 *key) {
  int i, h, l;
  if (!hex_str || !key) return -EINVAL;

  for (i = 0; i < 32; ++i) {
    h = hex_to_bin(hex_str[2 * i]);
    l = hex_to_bin(hex_str[(2 * i) + 1]);
    if (h == -1 || l == -1) return -EINVAL;
    key[i] = (h << 4) | l;
  }
  return 0;
}

void buffer_to_hex_string(const u8 *buffer, size_t buffer_size, char *hex_string, size_t hex_string_size) {
  size_t i;

  if (buffer == NULL || hex_string == NULL || hex_string_size < 2 * buffer_size + 1) {
    // Handle error: invalid parameters
    pr_err("buffer_to_hex_string: bad parameters supplied\n");
    return;
  }

  for (i = 0; i < buffer_size; ++i) {
    sprintf(hex_string + 2 * i, "%02x", buffer[i]);
  }
  hex_string[2 * buffer_size] = '\0';  // Null-terminate the string
}
