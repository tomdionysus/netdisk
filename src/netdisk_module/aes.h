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

#include <crypto/skcipher.h>

#define AES_BLOCKLEN 16  // Block length in bytes - AES is 128b block only
#define AES_KEYLEN 32

typedef struct AES_ctx {
  struct crypto_skcipher* rx_tfm;
  struct crypto_skcipher* tx_tfm;

  uint8_t rx_iv[AES_BLOCKLEN];
  uint8_t tx_iv[AES_BLOCKLEN];
} AES_ctx_t;

AES_ctx_t* AES_CBC_alloc(const uint8_t* key);
void AES_CBC_set_tx_iv(AES_ctx_t* ctx, const uint8_t* iv);
void AES_CBC_set_rx_iv(AES_ctx_t* ctx, const uint8_t* iv);
void AES_CBC_encrypt_buffer(AES_ctx_t* ctx, uint8_t* out, uint8_t* in, uint32_t length);
void AES_CBC_decrypt_buffer(AES_ctx_t* ctx, uint8_t* out, uint8_t* in, uint32_t length);
void AES_CBC_release(AES_ctx_t* ctx);

#endif