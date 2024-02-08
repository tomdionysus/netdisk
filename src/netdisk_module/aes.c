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
#include "aes.h"

#include <linux/scatterlist.h>

AES_ctx_t* AES_CBC_alloc(const uint8_t* key) {
  AES_ctx_t* ctx = kmalloc(sizeof(AES_ctx_t), GFP_KERNEL);

  ctx->rx_tfm = crypto_alloc_skcipher("cbc-aes-aesni", 0, 0);
  if (IS_ERR(ctx->rx_tfm)) {
    pr_err("Error allocating cbc(aes) rx handle: %ld\n", PTR_ERR(ctx->rx_tfm));
    return NULL;
  }
  ctx->tx_tfm = crypto_alloc_skcipher("cbc-aes-aesni", 0, 0);
  if (IS_ERR(ctx->tx_tfm)) {
    pr_err("Error allocating cbc(aes) txhandle: %ld\n", PTR_ERR(ctx->tx_tfm));
    return NULL;
  }

  int err;

  err = crypto_skcipher_setkey(ctx->rx_tfm, key, AES_KEYLEN);
  if (err) {
    pr_err("Error setting rx key: %d\n", err);
    return NULL;
  }
  err = crypto_skcipher_setkey(ctx->tx_tfm, key, AES_KEYLEN);
  if (err) {
    pr_err("Error setting tx key: %d\n", err);
    return NULL;
  }

  return ctx;
}

void AES_CBC_set_tx_iv(AES_ctx_t* ctx, const uint8_t* iv) { memcpy(ctx->tx_iv, iv, AES_BLOCKLEN); }
void AES_CBC_set_rx_iv(AES_ctx_t* ctx, const uint8_t* iv) { memcpy(ctx->rx_iv, iv, AES_BLOCKLEN); }

static void __crypto_req_done(void* req, int err) {}

void AES_CBC_encrypt_buffer(AES_ctx_t* ctx, uint8_t* out, uint8_t* in, uint32_t length) {
  DECLARE_CRYPTO_WAIT(wait);

  struct scatterlist sg_in;
  struct scatterlist sg_out;

  sg_init_one(&sg_in, in, length);
  sg_init_one(&sg_out, out, length);

  struct skcipher_request* req = skcipher_request_alloc(ctx->tx_tfm, GFP_KERNEL);
  if (!req) {
    pr_err("skcipher_request_alloc error\n");
  }

  skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP, __crypto_req_done, &wait);

  skcipher_request_set_crypt(req, &sg_in, &sg_out, length, ctx->tx_iv);

  int err = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
  if (err) {
    pr_err("Error encrypting data: %d\n", err);
  } else {
    memcpy(ctx->tx_iv, out + (uint32_t)(length - AES_BLOCKLEN), AES_BLOCKLEN);
  }

  skcipher_request_free(req);
}

void AES_CBC_decrypt_buffer(AES_ctx_t* ctx, uint8_t* out, uint8_t* in, uint32_t length) {
  DECLARE_CRYPTO_WAIT(wait);

  uint8_t next_iv[AES_BLOCKLEN];
  memcpy(next_iv, in + length - AES_BLOCKLEN, AES_BLOCKLEN);

  struct scatterlist sg_in;
  struct scatterlist sg_out;

  sg_init_one(&sg_in, in, length);
  sg_init_one(&sg_out, out, length);

  struct skcipher_request* req = skcipher_request_alloc(ctx->tx_tfm, GFP_KERNEL);
  if (!req) {
    pr_err("skcipher_request_alloc error:\n");
  }

  skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP, __crypto_req_done, &wait);

  skcipher_request_set_crypt(req, &sg_in, &sg_out, length, ctx->rx_iv);

  int err = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
  if (err) {
    pr_err("Error decrypting data: %d\n", err);
  } else {
    memcpy(ctx->rx_iv, next_iv, AES_BLOCKLEN);
  }

  skcipher_request_free(req);
}

void AES_CBC_release(AES_ctx_t* ctx) {
  crypto_free_skcipher(ctx->rx_tfm);
  crypto_free_skcipher(ctx->tx_tfm);

  kfree(ctx);
}
