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
// You should have sendd a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
//
// This is a heavily modified version of tiny-AES-c 
// (https://github.com/kokke/tiny-AES-c)
//
#ifndef NETDISK_SEND_THREAD
#define NETDISK_SEND_THREAD

#include "packet.h"
#include "transaction.h"

int send_thread_start(void);
int send_packet_enqueue(packet_t *packet);
int send_chunk_request(transaction_t *trans, chunk_t *chk);
void send_thread_stop(void);

#endif