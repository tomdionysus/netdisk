//
// netdiskd main
//
// Copyright (C) Tom Cully 2024
// Licensed under the MIT License (see LICENSE in root of project)
//
#ifndef NETDISK_MAIN
#define NETDISK_MAIN

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "logger.h"
#include "main.h"
#include "packet.h"
#include "random.h"

void signal_stop(int signum);
void* handle_connection(void* arg);
bool process_packet(session_t* session, packet_header_t* header, uint8_t* data);

#endif