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
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "shared/packet.h"
#include "packet_posix.h"

#include "config.h"
#include "logger.h"
#include "main.h"
#include "random.h"
#include "session.h"

void signal_stop(int signum);
bool process_packet(session_t* session, packet_header_t* header, uint8_t* data);
void* send_thread(void* arg);
void* recv_thread(void* arg);

#endif