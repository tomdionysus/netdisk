//
// libnetdisk profile functions
//
// Copyright (C) Tom Cully 2024
// Licensed under the MIT License (see LICENSE in root of project)
//
#ifndef NETDISK_PROFILE
#define NETDISK_PROFILE

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#define MAX_DOMAINS 100 // Maximum number of domains for profiling

// Structure to hold profile statistics for each domain
typedef struct {
    uint32_t domain_id;
    uint64_t min_time;
    uint64_t max_time;
    uint64_t total_time;
    uint64_t start_time;
    uint64_t num_samples;
} profile_stats_t;

void profile_clear_all();
void profile_start(uint32_t domain);
void profile_stop(uint32_t domain) ;
void profile_dump_all();

#endif