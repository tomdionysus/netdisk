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
#include <unistd.h>

#include "config.h"
#include "logger.h"
#include "main.h"
#include "packet.h"
#include "random.h"

void process_packet(packet_t* packet, struct sockaddr_in* addr);
void signal_stop(int signum);

#endif