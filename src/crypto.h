#ifndef KUGOU_TOOL_CRYPTO_H
#define KUGOU_TOOL_CRYPTO_H

#include "app.h"

void md5_hash(const uint8_t *data, size_t len, uint8_t out[16]);

typedef struct {
    uint32_t rk[44];
} Aes128Dec;

void aes128_dec_init(Aes128Dec *ctx, const uint8_t key[16]);
void aes128_cbc_decrypt(const Aes128Dec *ctx, const uint8_t iv[16],
                        uint8_t *data, size_t len);

bool base64_decode(const char *src, size_t srclen, uint8_t **out, size_t *outlen);

#endif
