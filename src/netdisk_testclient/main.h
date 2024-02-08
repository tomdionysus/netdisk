//
// netdisk_testclient main
//
// Copyright (C) Tom Cully 2024
// Licensed under the MIT License (see LICENSE in root of project)
//
#ifndef NETDISK_TESTCLIENT_MAIN
#define NETDISK_TESTCLIENT_MAIN

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <unistd.h>
#include <pthread.h>

#include "config.h"
#include "logger.h"
#include "main.h"
#include "packet.h"
#include "random.h"

bool process_packet(session_t* session, packet_header_t* header, uint8_t* data);
void signal_stop(int signum);

#endif