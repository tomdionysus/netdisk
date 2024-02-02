//
// libnetdisk logger
//
// Copyright (C) Tom Cully 2024
// Licensed under the MIT License (see LICENSE in root of project)
//
#include "logger.h"

uint8_t _log_level;

void log_set_level(uint8_t level) { _log_level = level; }

void log_raw(char* log, ...) {
  va_list args;
  va_start(args, log);

  char timebuffer[32];
  get_iso8601_time(timebuffer);
  printf("%s [-----] ", timebuffer);
  vprintf(log, args);
  printf("\n");
  va_end(args);
}

void log_debug(char* log, ...) {
  if (_log_level > LOG_LEVEL_DEBUG) return;

  va_list args;
  va_start(args, log);

  char timebuffer[32];
  get_iso8601_time(timebuffer);
  printf("%s [DEBUG] ", timebuffer);
  vprintf(log, args);
  printf("\n");
  va_end(args);
}

void log_info(char* log, ...) {
  if (_log_level > LOG_LEVEL_INFO) return;

  va_list args;
  va_start(args, log);

  char timebuffer[32];
  get_iso8601_time(timebuffer);
  printf("%s [INFO ] ", timebuffer);
  vprintf(log, args);
  printf("\n");
  va_end(args);
}

void log_warn(char* log, ...) {
  if (_log_level > LOG_LEVEL_WARN) return;

  va_list args;
  va_start(args, log);

  char timebuffer[32];
  get_iso8601_time(timebuffer);
  printf("%s [WARN ] ", timebuffer);
  vprintf(log, args);
  printf("\n");
  va_end(args);
}

void log_error(char* log, ...) {
  va_list args;
  va_start(args, log);

  char timebuffer[32];
  get_iso8601_time(timebuffer);
  printf("%s [ERROR] ", timebuffer);
  vprintf(log, args);
  printf("\n");
  va_end(args);
}

// Function to parse log level from string
log_level_t parse_log_level(const char* level) {
  if (strcasecmp(level, "debug") == 0) return LOG_LEVEL_DEBUG;
  if (strcasecmp(level, "info") == 0) return LOG_LEVEL_INFO;
  if (strcasecmp(level, "warn") == 0) return LOG_LEVEL_WARN;
  if (strcasecmp(level, "error") == 0) return LOG_LEVEL_ERROR;
  return LOG_LEVEL_UNKNOWN;
};

void get_iso8601_time(char* buffer) {
  if (buffer == NULL) {
    return;
  }

  time_t now;
  struct tm* tm_info;

  time(&now);
  tm_info = gmtime(&now);

  strftime(buffer, 20, "%Y-%m-%dT%H:%M:%S", tm_info);
}
