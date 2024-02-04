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
#ifndef AES
#define AES
#include <linux/types.h>

#define AES_BLOCKLEN 16  // Block length in bytes - AES is 128b block only

#define AES_KEYLEN 32
#define AES_keyExpSize 240

struct AES_ctx {
  u8 RoundKey[AES_keyExpSize];
  u8 Iv[AES_BLOCKLEN];
};

void AES_init_ctx(struct AES_ctx* ctx, const u8* key);
void AES_init_ctx_iv(struct AES_ctx* ctx, const u8* key, const u8* iv);
void AES_ctx_set_iv(struct AES_ctx* ctx, const u8* iv);
void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, u8* buf, size_t length);
void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, u8* buf, size_t length);

#endif