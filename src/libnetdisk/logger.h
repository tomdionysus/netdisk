//
// libnetdisk logger
//
// Copyright (C) Tom Cully 2024
// Licensed under the MIT License (see LICENSE in root of project)
//
#ifndef NETDISK_LOGGER
#define NETDISK_LOGGER

#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

typedef enum { LOG_LEVEL_DEBUG, LOG_LEVEL_INFO, LOG_LEVEL_WARN, LOG_LEVEL_ERROR, LOG_LEVEL_UNKNOWN } log_level_t;

extern uint8_t _log_level;

void log_set_level(uint8_t level);

void log_raw(char* log, ...);
void log_debug(char* log, ...);
void log_info(char* log, ...);
void log_warn(char* log, ...);
void log_error(char* log, ...);

log_level_t parse_log_level(const char* level);

void get_iso8601_time(char* buffer);

#endif
