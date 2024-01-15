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
#ifndef NETDISK_UTIL
#define NETDISK_UTIL

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/errno.h>

int parse_key(const char *hex_str, u8 *key);
void buffer_to_hex_string(const u8 *buffer, size_t buffer_size, char *hex_string, size_t hex_string_size);

#endif