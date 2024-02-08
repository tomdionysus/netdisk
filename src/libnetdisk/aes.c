#include "aes.h"

AES_ctx_t* AES_CBC_alloc(const uint8_t* key) {
	AES_ctx_t* ctx = malloc(sizeof(AES_ctx_t));
	if(!ctx) return NULL;

	ctx->openssl_ctx = EVP_CIPHER_CTX_new();
	memcpy(&ctx->key, key, AES_KEYLEN);

	return ctx;
}

void AES_CBC_set_tx_iv(AES_ctx_t* ctx, const uint8_t* iv) {
	memcpy(&ctx->tx_iv, iv, AES_BLOCKLEN);
}

void AES_CBC_set_rx_iv(AES_ctx_t* ctx, const uint8_t* iv) {
	memcpy(&ctx->rx_iv, iv, AES_BLOCKLEN);
}

bool AES_CBC_encrypt_buffer(AES_ctx_t* ctx, uint8_t* out, uint8_t* in, uint32_t length) {
	if(1 != EVP_EncryptInit_ex(ctx->openssl_ctx, EVP_aes_256_cbc(), NULL, (const unsigned char*)&ctx->key, (const unsigned char*)&ctx->tx_iv)) {
		return false;
	}

    int outlen;

    // Provide the plaintext to be encrypted
    if(1 != EVP_EncryptUpdate(ctx->openssl_ctx, out, &outlen, in, length)) {
    	return false;
    }

    // Finalize the encryption
    if(1 != EVP_EncryptFinal_ex(ctx->openssl_ctx, out + length, &outlen)) {
    	return false;
    }

    if(outlen!=length) {
    	return false;
    }

    // Set the last decrypted block as new IV
    memcpy(&ctx->tx_iv, out+length-AES_BLOCKLEN, AES_BLOCKLEN);

    return true;
}

bool AES_CBC_decrypt_buffer(AES_ctx_t* ctx, uint8_t* out, uint8_t* in, uint32_t length) {

	// Keep a copy of the original last encrypted block (in case out == in)
	uint8_t last_cyphertext[AES_BLOCKLEN];
	memcpy(&last_cyphertext, out+length-AES_BLOCKLEN, AES_BLOCKLEN);

	if(1 != EVP_DecryptInit_ex(ctx->openssl_ctx, EVP_aes_256_cbc(), NULL, (const unsigned char*)&ctx->key, (const unsigned char*)&ctx->tx_iv)) {
		return false;
	}

    int outlen;

    // Provide the plaintext to be Decrypted
    if(1 != EVP_DecryptUpdate(ctx->openssl_ctx, out, &outlen, in, length)) {
    	return false;
    }

    // Finalize the Decryption
    if(1 != EVP_DecryptFinal_ex(ctx->openssl_ctx, out + length, &outlen)) {
    	return false;
    }

    if(outlen!=length) {
    	return false;
    }

    // Set the original last encrypted block as new IV
    memcpy(&ctx->tx_iv, last_cyphertext, AES_BLOCKLEN);

    return true;
}

void AES_CBC_release(AES_ctx_t* ctx) {

}
