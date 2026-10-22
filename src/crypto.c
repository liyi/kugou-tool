#include "crypto.h"
#include "util.h"

#include <string.h>

/* ---------------- MD5 ---------------- */

typedef struct {
    uint32_t h[4];
    uint64_t total;
    uint8_t buf[64];
    size_t used;
} Md5Ctx;

static uint32_t rotl32(uint32_t x, unsigned n)
{
    return (x << n) | (x >> (32 - n));
}

static void md5_transform(Md5Ctx *ctx, const uint8_t block[64])
{
    static const uint32_t K[64] = {
        0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu,
        0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
        0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu,
        0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
        0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau,
        0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
        0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu,
        0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
        0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu,
        0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
        0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u,
        0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
        0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u,
        0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
        0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u,
        0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u
    };
    static const unsigned S[64] = {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    };
    uint32_t M[16];
    uint32_t A = ctx->h[0];
    uint32_t B = ctx->h[1];
    uint32_t C = ctx->h[2];
    uint32_t D = ctx->h[3];
    unsigned i;

    for (i = 0; i < 16; ++i) {
        M[i] = (uint32_t)block[i * 4] |
               ((uint32_t)block[i * 4 + 1] << 8) |
               ((uint32_t)block[i * 4 + 2] << 16) |
               ((uint32_t)block[i * 4 + 3] << 24);
    }
    for (i = 0; i < 64; ++i) {
        uint32_t F;
        unsigned g;
        uint32_t tmp;
        if (i < 16) {
            F = (B & C) | ((~B) & D);
            g = i;
        } else if (i < 32) {
            F = (D & B) | ((~D) & C);
            g = (5 * i + 1) & 15;
        } else if (i < 48) {
            F = B ^ C ^ D;
            g = (3 * i + 5) & 15;
        } else {
            F = C ^ (B | (~D));
            g = (7 * i) & 15;
        }
        tmp = D;
        D = C;
        C = B;
        B = B + rotl32(A + F + K[i] + M[g], S[i]);
        A = tmp;
    }
    ctx->h[0] += A;
    ctx->h[1] += B;
    ctx->h[2] += C;
    ctx->h[3] += D;
}

static void md5_init(Md5Ctx *ctx)
{
    ctx->h[0] = 0x67452301u;
    ctx->h[1] = 0xefcdab89u;
    ctx->h[2] = 0x98badcfeu;
    ctx->h[3] = 0x10325476u;
    ctx->total = 0;
    ctx->used = 0;
}

static void md5_update(Md5Ctx *ctx, const uint8_t *data, size_t len)
{
    ctx->total += (uint64_t)len;
    while (len > 0) {
        size_t space = sizeof(ctx->buf) - ctx->used;
        size_t take = len < space ? len : space;
        memcpy(ctx->buf + ctx->used, data, take);
        ctx->used += take;
        data += take;
        len -= take;
        if (ctx->used == sizeof(ctx->buf)) {
            md5_transform(ctx, ctx->buf);
            ctx->used = 0;
        }
    }
}

static void md5_final(Md5Ctx *ctx, uint8_t out[16])
{
    uint64_t bits = ctx->total * 8ULL;
    uint8_t pad[72];
    size_t padlen;
    unsigned i;

    pad[0] = 0x80;
    memset(pad + 1, 0, sizeof(pad) - 1);
    padlen = (ctx->used < 56) ? (56 - ctx->used) : (120 - ctx->used);
    md5_update(ctx, pad, padlen);
    for (i = 0; i < 8; ++i) {
        pad[i] = (uint8_t)(bits >> (8 * i));
    }
    md5_update(ctx, pad, 8);
    for (i = 0; i < 4; ++i) {
        out[i * 4] = (uint8_t)(ctx->h[i]);
        out[i * 4 + 1] = (uint8_t)(ctx->h[i] >> 8);
        out[i * 4 + 2] = (uint8_t)(ctx->h[i] >> 16);
        out[i * 4 + 3] = (uint8_t)(ctx->h[i] >> 24);
    }
}

void md5_hash(const uint8_t *data, size_t len, uint8_t out[16])
{
    Md5Ctx ctx;
    md5_init(&ctx);
    md5_update(&ctx, data, len);
    md5_final(&ctx, out);
}

/* ---------------- AES-128 ---------------- */

static const uint8_t SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t INV_SBOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static const uint8_t RCON[11] = { 0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

static uint32_t sub_word(uint32_t w)
{
    return ((uint32_t)SBOX[(w >> 24) & 0xff] << 24) |
           ((uint32_t)SBOX[(w >> 16) & 0xff] << 16) |
           ((uint32_t)SBOX[(w >> 8) & 0xff] << 8) |
           (uint32_t)SBOX[w & 0xff];
}

void aes128_dec_init(Aes128Dec *ctx, const uint8_t key[16])
{
    unsigned i;
    for (i = 0; i < 4; ++i) {
        ctx->rk[i] = ((uint32_t)key[i * 4] << 24) |
                     ((uint32_t)key[i * 4 + 1] << 16) |
                     ((uint32_t)key[i * 4 + 2] << 8) |
                     (uint32_t)key[i * 4 + 3];
    }
    for (i = 4; i < 44; ++i) {
        uint32_t temp = ctx->rk[i - 1];
        if (i % 4 == 0) {
            temp = sub_word((temp << 8) | (temp >> 24)) ^ ((uint32_t)RCON[i / 4] << 24);
        }
        ctx->rk[i] = ctx->rk[i - 4] ^ temp;
    }
}

static uint8_t xtime(uint8_t x)
{
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

static uint8_t gmul(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    unsigned i;
    for (i = 0; i < 8; ++i) {
        if (b & 1) p ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return p;
}

static void add_round_key(uint8_t state[16], const uint32_t *rk)
{
    unsigned c;
    for (c = 0; c < 4; ++c) {
        uint32_t w = rk[c];
        state[c * 4] ^= (uint8_t)(w >> 24);
        state[c * 4 + 1] ^= (uint8_t)(w >> 16);
        state[c * 4 + 2] ^= (uint8_t)(w >> 8);
        state[c * 4 + 3] ^= (uint8_t)w;
    }
}

static void inv_shift_rows(uint8_t s[16])
{
    uint8_t t;
    t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
    t = s[2]; s[2] = s[10]; s[10] = t;
    t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
}

static void inv_sub_bytes(uint8_t s[16])
{
    unsigned i;
    for (i = 0; i < 16; ++i) s[i] = INV_SBOX[s[i]];
}

static void inv_mix_columns(uint8_t s[16])
{
    unsigned c;
    for (c = 0; c < 4; ++c) {
        uint8_t a0 = s[c * 4];
        uint8_t a1 = s[c * 4 + 1];
        uint8_t a2 = s[c * 4 + 2];
        uint8_t a3 = s[c * 4 + 3];
        s[c * 4] = gmul(a0, 0x0e) ^ gmul(a1, 0x0b) ^ gmul(a2, 0x0d) ^ gmul(a3, 0x09);
        s[c * 4 + 1] = gmul(a0, 0x09) ^ gmul(a1, 0x0e) ^ gmul(a2, 0x0b) ^ gmul(a3, 0x0d);
        s[c * 4 + 2] = gmul(a0, 0x0d) ^ gmul(a1, 0x09) ^ gmul(a2, 0x0e) ^ gmul(a3, 0x0b);
        s[c * 4 + 3] = gmul(a0, 0x0b) ^ gmul(a1, 0x0d) ^ gmul(a2, 0x09) ^ gmul(a3, 0x0e);
    }
}

static void aes128_decrypt_block(const Aes128Dec *ctx, const uint8_t in[16], uint8_t out[16])
{
    uint8_t s[16];
    int round;
    unsigned i;
    memcpy(s, in, 16);
    add_round_key(s, ctx->rk + 40);
    for (round = 9; round >= 1; --round) {
        inv_shift_rows(s);
        inv_sub_bytes(s);
        add_round_key(s, ctx->rk + round * 4);
        inv_mix_columns(s);
    }
    inv_shift_rows(s);
    inv_sub_bytes(s);
    add_round_key(s, ctx->rk);
    for (i = 0; i < 16; ++i) out[i] = s[i];
}

void aes128_cbc_decrypt(const Aes128Dec *ctx, const uint8_t iv[16],
                        uint8_t *data, size_t len)
{
    uint8_t prev[16];
    uint8_t cipher[16];
    uint8_t plain[16];
    size_t off;
    memcpy(prev, iv, 16);
    for (off = 0; off + 16 <= len; off += 16) {
        unsigned i;
        memcpy(cipher, data + off, 16);
        aes128_decrypt_block(ctx, cipher, plain);
        for (i = 0; i < 16; ++i) data[off + i] = plain[i] ^ prev[i];
        memcpy(prev, cipher, 16);
    }
}

/* ---------------- Base64 ---------------- */

static int b64_value(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') return (int)(c - 'A');
    if (c >= 'a' && c <= 'z') return (int)(c - 'a') + 26;
    if (c >= '0' && c <= '9') return (int)(c - '0') + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

bool base64_decode(const char *src, size_t srclen, uint8_t **out, size_t *outlen)
{
    size_t i;
    size_t o = 0;
    uint8_t *buf;
    uint32_t acc = 0;
    unsigned bits = 0;
    bool seen_pad = false;

    *out = NULL;
    *outlen = 0;
    if (srclen == 0) {
        *out = (uint8_t *)xmalloc(1);
        return *out != NULL;
    }
    buf = (uint8_t *)xmalloc((srclen / 4 + 1) * 3 + 4);
    if (!buf) return false;

    for (i = 0; i < srclen; ++i) {
        unsigned char c = (unsigned char)src[i];
        int v;
        if (c == '=') {
            seen_pad = true;
            continue;
        }
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        if (seen_pad) {
            free(buf);
            return false;
        }
        v = b64_value(c);
        if (v < 0) {
            free(buf);
            return false;
        }
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            buf[o++] = (uint8_t)(acc >> bits);
            acc &= (1u << bits) - 1;
        }
    }
    if (bits >= 6) {
        free(buf);
        return false;
    }
    *out = buf;
    *outlen = o;
    return true;
}
