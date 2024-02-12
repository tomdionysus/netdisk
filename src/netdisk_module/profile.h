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
#ifndef NETDISK_PROFILE
#define NETDISK_PROFILE

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/time.h>

#define MAX_DOMAINS 100 // Maximum number of domains for profiling

// Structure to hold profile statistics for each domain
typedef struct {
    uint32_t domain_id;
    uint64_t min_time;
    uint64_t max_time;
    uint64_t total_time;
    uint64_t num_samples;
    uint64_t start_time;
} profile_stats_t;

void profile_clear_all();
void profile_start(uint32_t domain);
void profile_stop(uint32_t domain);
void profile_dump_all();

#endif
