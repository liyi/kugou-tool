#include "audio.h"
#include "crypto.h"
#include "inflate.h"
#include "resource.h"
#include "util.h"
#include <strsafe.h>

#include <string.h>

static const uint8_t KGM_MAGIC[16] = {
    0x7C, 0xD5, 0x32, 0xEB, 0x86, 0x02, 0x7F, 0x4B,
    0xA8, 0xAF, 0xA6, 0x8E, 0x0F, 0xFF, 0x99, 0x14
};

static const uint8_t VPR_MAGIC[16] = {
    0x05, 0x28, 0xBC, 0x96, 0xE9, 0xE4, 0x5A, 0x43,
    0x91, 0xAA, 0xBD, 0xD0, 0x7A, 0xF5, 0x36, 0x31
};

static const uint8_t MEND_TABLE[272] = {
    0xB8, 0xD5, 0x3D, 0xB2, 0xE9, 0xAF, 0x78, 0x8C, 0x83, 0x33, 0x71, 0x51, 0x76, 0xA0, 0xCD, 0x37,
    0x2F, 0x3E, 0x35, 0x8D, 0xA9, 0xBE, 0x98, 0xB7, 0xE7, 0x8C, 0x22, 0xCE, 0x5A, 0x61, 0xDF, 0x68,
    0x69, 0x89, 0xFE, 0xA5, 0xB6, 0xDE, 0xA9, 0x77, 0xFC, 0xC8, 0xBD, 0xBD, 0xE5, 0x6D, 0x3E, 0x5A,
    0x36, 0xEF, 0x69, 0x4E, 0xBE, 0xE1, 0xE9, 0x66, 0x1C, 0xF3, 0xD9, 0x02, 0xB6, 0xF2, 0x12, 0x9B,
    0x44, 0xD0, 0x6F, 0xB9, 0x35, 0x89, 0xB6, 0x46, 0x6D, 0x73, 0x82, 0x06, 0x69, 0xC1, 0xED, 0xD7,
    0x85, 0xC2, 0x30, 0xDF, 0xA2, 0x62, 0xBE, 0x79, 0x2D, 0x62, 0x62, 0x3D, 0x0D, 0x7E, 0xBE, 0x48,
    0x89, 0x23, 0x02, 0xA0, 0xE4, 0xD5, 0x75, 0x51, 0x32, 0x02, 0x53, 0xFD, 0x16, 0x3A, 0x21, 0x3B,
    0x16, 0x0F, 0xC3, 0xB2, 0xBB, 0xB3, 0xE2, 0xBA, 0x3A, 0x3D, 0x13, 0xEC, 0xF6, 0x01, 0x45, 0x84,
    0xA5, 0x70, 0x0F, 0x93, 0x49, 0x0C, 0x64, 0xCD, 0x31, 0xD5, 0xCC, 0x4C, 0x07, 0x01, 0x9E, 0x00,
    0x1A, 0x23, 0x90, 0xBF, 0x88, 0x1E, 0x3B, 0xAB, 0xA6, 0x3E, 0xC4, 0x73, 0x47, 0x10, 0x7E, 0x3B,
    0x5E, 0xBC, 0xE3, 0x00, 0x84, 0xFF, 0x09, 0xD4, 0xE0, 0x89, 0x0F, 0x5B, 0x58, 0x70, 0x4F, 0xFB,
    0x65, 0xD8, 0x5C, 0x53, 0x1B, 0xD3, 0xC8, 0xC6, 0xBF, 0xEF, 0x98, 0xB0, 0x50, 0x4F, 0x0F, 0xEA,
    0xE5, 0x83, 0x58, 0x8C, 0x28, 0x2C, 0x84, 0x67, 0xCD, 0xD0, 0x9E, 0x47, 0xDB, 0x27, 0x50, 0xCA,
    0xF4, 0x63, 0x63, 0xE8, 0x97, 0x7F, 0x1B, 0x4B, 0x0C, 0xC2, 0xC1, 0x21, 0x4C, 0xCC, 0x58, 0xF5,
    0x94, 0x52, 0xA3, 0xF3, 0xD3, 0xE0, 0x68, 0xF4, 0x00, 0x23, 0xF3, 0x5E, 0x0A, 0x7B, 0x93, 0xDD,
    0xAB, 0x12, 0xB2, 0x13, 0xE8, 0x84, 0xD7, 0xA7, 0x9F, 0x0F, 0x32, 0x4C, 0x55, 0x1D, 0x04, 0x36,
    0x52, 0xDC, 0x03, 0xF3, 0xF9, 0x4E, 0x42, 0xE9, 0x3D, 0x61, 0xEF, 0x7C, 0xB6, 0xB3, 0x93, 0x50
};

#define PUBKEY_MAX (32u * 1024u * 1024u)
#define QMC_STREAM_SIZE (0x1400u + 512u)

typedef enum {
    DEC_V3 = 1,
    DEC_QMC2 = 2
} DecryptMode;

typedef struct {
    int type; /* 1 = RC4, 2 = MAP */
    uint8_t *key;
    size_t keylen;
    double hash;
    uint8_t *stream;
    uint8_t mapkey[128];
} QmcCtx;

struct AudioDecryptor {
    HANDLE file;
    uint64_t file_size;
    uint64_t audio_offset;
    uint64_t audio_size;
    uint32_t version;
    DecryptMode mode;
    uint8_t own_key[17];
    QmcCtx qmc;
};

static uint8_t *g_pubkey;
static size_t g_pubkey_len;
static int g_pubkey_state; /* 0=untried, 1=ok, -1=failed */
static wchar_t g_pubkey_err[ERR_CAP];

static uint32_t rd_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t rd_be64(const uint8_t *p)
{
    uint64_t v = 0;
    int i;
    for (i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}

static void wr_be64(uint8_t *p, uint64_t v)
{
    int i;
    for (i = 7; i >= 0; --i) {
        p[i] = (uint8_t)v;
        v >>= 8;
    }
}

bool AudioMagicOk(const uint8_t *data, size_t len)
{
    if (!data || len < 16) return false;
    return memcmp(data, KGM_MAGIC, 16) == 0 || memcmp(data, VPR_MAGIC, 16) == 0;
}

static bool load_pubkey(wchar_t *err, size_t errcap)
{
    HRSRC hr;
    HGLOBAL hg;
    const uint8_t *data;
    DWORD size;
    uint8_t *out = NULL;
    size_t outlen = 0;
    wchar_t zerr[ERR_CAP];

    if (g_pubkey_state == 1) return true;
    if (g_pubkey_state == -1) {
        StringCchCopyW(err, errcap, g_pubkey_err);
        return false;
    }
    hr = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_KGM_KEY), RT_RCDATA);
    if (!hr) {
        StringCchCopyW(g_pubkey_err, ERR_CAP, L"解密失败：内置密钥表缺失");
        g_pubkey_state = -1;
        StringCchCopyW(err, errcap, g_pubkey_err);
        return false;
    }
    hg = LoadResource(NULL, hr);
    data = (const uint8_t *)LockResource(hg);
    size = SizeofResource(NULL, hr);
    if (!data || size == 0) {
        StringCchCopyW(g_pubkey_err, ERR_CAP, L"解密失败：内置密钥表不可用");
        g_pubkey_state = -1;
        StringCchCopyW(err, errcap, g_pubkey_err);
        return false;
    }
    if (!zlib_decompress(data, size, PUBKEY_MAX, &out, &outlen, zerr, ERR_CAP)) {
        StringCchPrintfW(g_pubkey_err, ERR_CAP, L"解密失败：内置密钥表损坏（%s）", zerr);
        g_pubkey_state = -1;
        StringCchCopyW(err, errcap, g_pubkey_err);
        return false;
    }
    g_pubkey = out;
    g_pubkey_len = outlen;
    g_pubkey_state = 1;
    return true;
}

static uint8_t scramble_byte(uint8_t v)
{
    return (uint8_t)(v ^ (uint8_t)((v & 0x0F) << 4));
}

static bool read_at(HANDLE h, uint64_t offset, uint8_t *buf, size_t len,
                    wchar_t *err, size_t errcap)
{
    LARGE_INTEGER pos;
    size_t total = 0;
    pos.QuadPart = (LONGLONG)offset;
    if (!SetFilePointerEx(h, pos, NULL, FILE_BEGIN)) {
        FormatWin32Error(L"读取文件失败", GetLastError(), err, errcap);
        return false;
    }
    while (total < len) {
        DWORD want = (DWORD)(len - total > 0x7FFFFFFF ? 0x7FFFFFFF : len - total);
        DWORD got = 0;
        if (!ReadFile(h, buf + total, want, &got, NULL)) {
            FormatWin32Error(L"读取文件失败", GetLastError(), err, errcap);
            return false;
        }
        if (got == 0) {
            StringCchCopyW(err, errcap, L"解密失败：文件已截断");
            return false;
        }
        total += got;
    }
    return true;
}

/* ---------------- TEA ---------------- */

static uint32_t tea_round(uint32_t v, uint32_t sum, uint32_t k1, uint32_t k2)
{
    return ((v << 4) + k1) ^ (v + sum) ^ ((v >> 5) + k2);
}

static uint64_t tea_decrypt_block(uint64_t value, const uint32_t key[4])
{
    uint32_t y = (uint32_t)(value >> 32);
    uint32_t z = (uint32_t)value;
    uint32_t sum = 16u * 0x9e3779b9u;
    int i;
    for (i = 0; i < 16; ++i) {
        z -= tea_round(y, sum, key[2], key[3]);
        y -= tea_round(z, sum, key[0], key[1]);
        sum -= 0x9e3779b9u;
    }
    return ((uint64_t)y << 32) | (uint64_t)z;
}

static void tea_decrypt_round(uint8_t out[8], const uint8_t in[8],
                              uint64_t *iv1, uint64_t *iv2, const uint32_t key[4])
{
    uint64_t c = rd_be64(in);
    uint64_t next_iv2 = tea_decrypt_block(c ^ *iv2, key);
    uint64_t plain = next_iv2 ^ *iv1;
    *iv1 = c;
    *iv2 = next_iv2;
    wr_be64(out, plain);
}

static bool tea_cbc_decrypt(const uint8_t *cipher, size_t cipherlen,
                            const uint32_t key[4],
                            uint8_t **out, size_t *outlen)
{
    uint8_t header[16];
    uint64_t iv1 = 0;
    uint64_t iv2 = 0;
    size_t ipos = 0;
    size_t hskip;
    size_t real;
    size_t copy_len;
    uint8_t *result;
    uint8_t *p;

    *out = NULL;
    *outlen = 0;
    if (cipherlen < 16 || (cipherlen % 8) != 0) return false;
    tea_decrypt_round(header, cipher + ipos, &iv1, &iv2, key);
    ipos += 8;
    tea_decrypt_round(header + 8, cipher + ipos, &iv1, &iv2, key);
    ipos += 8;

    hskip = 1u + (size_t)(header[0] & 7u) + 2u;
    if (cipherlen < hskip + 7u) return false;
    real = cipherlen - hskip - 7u;
    if (real == 0) return false;
    result = (uint8_t *)xmalloc(real);
    if (!result) return false;
    copy_len = 16u - hskip;
    if (copy_len > real) copy_len = real;
    memcpy(result, header + hskip, copy_len);
    p = result + copy_len;
    if (real != copy_len) {
        size_t loops = (cipherlen - 24u) / 8u;
        size_t i;
        if (copy_len + loops * 8u + 1u != real) {
            free(result);
            return false;
        }
        for (i = 0; i < loops; ++i) {
            tea_decrypt_round(p, cipher + ipos, &iv1, &iv2, key);
            ipos += 8;
            p += 8;
        }
        tea_decrypt_round(header + 8, cipher + ipos, &iv1, &iv2, key);
        p[0] = header[8];
    }
    if ((rd_be64(header + 8) << 8) != 0) {
        free(result);
        return false;
    }
    *out = result;
    *outlen = real;
    return true;
}

static bool ekey_v1_decode(const uint8_t *ekey, size_t ekey_len,
                           uint8_t **out, size_t *outlen)
{
    uint8_t *raw = NULL;
    size_t rawlen = 0;
    uint32_t tea_key[4];
    uint8_t *plain = NULL;
    size_t plainlen = 0;
    uint8_t *result;

    *out = NULL;
    *outlen = 0;
    if (!base64_decode((const char *)ekey, ekey_len, &raw, &rawlen)) return false;
    if (rawlen < 24) {
        free(raw);
        return false;
    }
    tea_key[0] = 0x69005600u | ((uint32_t)raw[0] << 16) | (uint32_t)raw[1];
    tea_key[1] = 0x46003800u | ((uint32_t)raw[2] << 16) | (uint32_t)raw[3];
    tea_key[2] = 0x2B002000u | ((uint32_t)raw[4] << 16) | (uint32_t)raw[5];
    tea_key[3] = 0x15000B00u | ((uint32_t)raw[6] << 16) | (uint32_t)raw[7];
    if (!tea_cbc_decrypt(raw + 8, rawlen - 8, tea_key, &plain, &plainlen)) {
        free(raw);
        return false;
    }
    if (plainlen > 65536u - 8u) {
        free(raw);
        free(plain);
        return false;
    }
    result = (uint8_t *)xmalloc(8u + plainlen);
    if (!result) {
        free(raw);
        free(plain);
        return false;
    }
    memcpy(result, raw, 8);
    memcpy(result + 8, plain, plainlen);
    *out = result;
    *outlen = 8u + plainlen;
    free(raw);
    free(plain);
    return true;
}

static bool ekey_decode(const char *ekey, uint8_t **key, size_t *keylen)
{
    static const char v2prefix[] = "UVFNdXNpYyBFbmNWMixLZXk6";
    static const uint32_t v2key1[4] = { 0x3338365Au, 0x4A592140u, 0x232A2425u, 0x5E262928u };
    static const uint32_t v2key2[4] = { 0x2A2A2321u, 0x28232425u, 0x265E6131u, 0x635A2C54u };
    size_t len = strlen(ekey);
    size_t prefix_len = sizeof(v2prefix) - 1;

    *key = NULL;
    *keylen = 0;
    if (len >= prefix_len && memcmp(ekey, v2prefix, prefix_len) == 0) {
        const uint8_t *body = (const uint8_t *)(ekey + prefix_len);
        size_t bodylen = len - prefix_len;
        uint8_t *stage1 = NULL;
        size_t stage1len = 0;
        uint8_t *stage2 = NULL;
        size_t stage2len = 0;
        bool ok;
        if (!tea_cbc_decrypt(body, bodylen, v2key1, &stage1, &stage1len)) return false;
        ok = tea_cbc_decrypt(stage1, stage1len, v2key2, &stage2, &stage2len);
        free(stage1);
        if (!ok) return false;
        ok = ekey_v1_decode(stage2, stage2len, key, keylen);
        free(stage2);
        return ok;
    }
    return ekey_v1_decode((const uint8_t *)ekey, len, key, keylen);
}

/* ---------------- QMC2 ---------------- */

static uint64_t qmc_hash_key(const uint8_t *key, size_t len)
{
    uint32_t h = 1;
    size_t i;
    for (i = 0; i < len; ++i) {
        uint32_t nh;
        if (key[i] == 0) continue;
        nh = h * (uint32_t)key[i];
        if (nh <= h) break;
        h = nh;
    }
    return (uint64_t)h;
}

static size_t qmc_segment_key(double key_hash, size_t segment_id, uint8_t seed)
{
    double result;
    if (seed == 0) return 0;
    result = key_hash / ((double)seed * (double)(segment_id + 1)) * 100.0;
    if (!(result >= 0.0)) return 0;
    if (result >= (double)SIZE_MAX) return SIZE_MAX;
    return (size_t)result;
}

static bool qmc_rc4_init(QmcCtx *q, const uint8_t *key, size_t n)
{
    uint8_t *s;
    size_t i;
    size_t j = 0;
    size_t si = 0;
    size_t sj = 0;
    size_t x;

    if (n == 0 || n > 65536u) return false;
    s = (uint8_t *)xmalloc(n);
    q->key = (uint8_t *)xmalloc(n);
    q->stream = (uint8_t *)xmalloc(QMC_STREAM_SIZE);
    if (!s || !q->key || !q->stream) {
        free(s);
        free(q->key);
        free(q->stream);
        q->key = NULL;
        q->stream = NULL;
        return false;
    }
    memcpy(q->key, key, n);
    q->keylen = n;
    q->hash = (double)qmc_hash_key(key, n);
    for (i = 0; i < n; ++i) s[i] = (uint8_t)i;
    for (i = 0; i < n; ++i) {
        uint8_t t;
        j = (j + (size_t)s[i] + key[i]) % n;
        t = s[i]; s[i] = s[j]; s[j] = t;
    }
    for (x = 0; x < QMC_STREAM_SIZE; ++x) {
        uint8_t t;
        si = (si + 1) % n;
        sj = (sj + (size_t)s[si]) % n;
        t = s[si]; s[si] = s[sj]; s[sj] = t;
        q->stream[x] = s[((size_t)s[si] + (size_t)s[sj]) % n];
    }
    free(s);
    q->type = 1;
    return true;
}

static bool qmc_map_init(QmcCtx *q, const uint8_t *key, size_t n)
{
    size_t i;
    if (n == 0) return false;
    q->key = (uint8_t *)xmalloc(n);
    if (!q->key) return false;
    memcpy(q->key, key, n);
    q->keylen = n;
    for (i = 0; i < 128; ++i) {
        size_t j = (i * i + 71214u) % n;
        unsigned shift = (unsigned)((j + 4) % 8);
        q->mapkey[i] = (uint8_t)(((uint32_t)key[j] << shift) | ((uint32_t)key[j] >> shift));
    }
    q->type = 2;
    return true;
}

static bool qmc_init(QmcCtx *q, const uint8_t *key, size_t len)
{
    memset(q, 0, sizeof(*q));
    if (len < 300) {
        return qmc_map_init(q, key, len);
    }
    return qmc_rc4_init(q, key, len);
}

static void qmc_free(QmcCtx *q)
{
    free(q->key);
    free(q->stream);
    memset(q, 0, sizeof(*q));
}

static void qmc_decrypt(QmcCtx *q, uint8_t *data, size_t len, uint64_t offset)
{
    size_t pos = 0;
    size_t n = q->keylen;
    size_t off = (size_t)offset;

    if (q->type == 2) {
        size_t i;
        for (i = 0; i < len; ++i) {
            size_t idx = (off <= 0x7FFFu) ? off : (off % 0x7FFFu);
            data[i] ^= q->mapkey[idx % 128u];
            ++off;
        }
        return;
    }
    if (off < 0x80u) {
        size_t count = len;
        size_t k;
        if (count > 0x80u - off) count = 0x80u - off;
        for (k = 0; k < count; ++k) {
            size_t idx = qmc_segment_key(q->hash, off, q->key[off % n]) % n;
            data[k] ^= q->key[idx];
            ++off;
        }
        pos = count;
    }
    while (pos < len) {
        size_t segment = off / 0x1400u;
        size_t within = off % 0x1400u;
        size_t skip = qmc_segment_key(q->hash, segment, q->key[segment % n]) & 0x1FFu;
        size_t count = len - pos;
        size_t k;
        if (count > 0x1400u - within) count = 0x1400u - within;
        for (k = 0; k < count; ++k) {
            data[pos + k] ^= q->stream[skip + within + k];
        }
        pos += count;
        off += count;
    }
}

/* ---------------- Open / read ---------------- */

static uint64_t pubkey_required_blocks(uint64_t audio_size)
{
    return (audio_size + 15u) / 16u;
}

static bool open_v3(AudioDecryptor *d, const uint8_t *header, wchar_t *err, size_t errcap)
{
    uint64_t blocks;
    if (!load_pubkey(err, errcap)) return false;
    memcpy(d->own_key, header + 0x1C, 16);
    d->own_key[16] = 0;
    blocks = pubkey_required_blocks(d->audio_size);
    if (blocks > (uint64_t)g_pubkey_len) {
        StringCchCopyW(err, errcap, L"解密失败：文件超出内置密钥表支持范围");
        return false;
    }
    d->mode = DEC_V3;
    return true;
}

static bool open_v5(AudioDecryptor *d, const uint8_t *header,
                    KeyDbCache *cache, const wchar_t *setting,
                    wchar_t *err, size_t errcap)
{
    uint32_t hash_len = rd_le32(header + 0x44);
    char hash[40];
    const char *ekey;
    uint8_t *key = NULL;
    size_t keylen = 0;

    if (hash_len != 0x20) {
        StringCchCopyW(err, errcap, L"解密失败：文件头损坏（密钥标识）");
        return false;
    }
    memcpy(hash, header + 0x48, 32);
    hash[32] = '\0';
    if (!cache) {
        StringCchCopyW(err, errcap, L"需要密钥库：未初始化");
        return false;
    }
    ekey = KeyDbCache_Lookup(cache, setting, hash, err, errcap);
    if (!ekey) return false;
    if (!ekey_decode(ekey, &key, &keylen)) {
        StringCchCopyW(err, errcap, L"解密失败：密钥数据无效");
        return false;
    }
    if (!qmc_init(&d->qmc, key, keylen)) {
        free(key);
        StringCchCopyW(err, errcap, L"解密失败：密钥数据无效");
        return false;
    }
    free(key);
    d->mode = DEC_QMC2;
    return true;
}

static AudioDecryptor *audio_open_impl(const wchar_t *path, KeyDbCache *cache,
                                       const wchar_t *setting,
                                       wchar_t *err, size_t errcap)
{
    AudioDecryptor *d;
    wchar_t *lp;
    LARGE_INTEGER size;
    uint8_t header[1024];
    uint64_t audio_offset;
    uint32_t version;
    FileKind kind = KindFromPath(path);

    if (!IsSupportedAudioKind(kind)) {
        StringCchCopyW(err, errcap, L"不支持的文件类型");
        return NULL;
    }
    d = (AudioDecryptor *)xcalloc(1, sizeof(AudioDecryptor));
    if (!d) {
        StringCchCopyW(err, errcap, L"内存不足");
        return NULL;
    }
    d->file = INVALID_HANDLE_VALUE;
    lp = MakeLongPath(path);
    if (!lp) {
        StringCchCopyW(err, errcap, L"内存不足");
        free(d);
        return NULL;
    }
    d->file = CreateFileW(lp, GENERIC_READ, FILE_SHARE_READ,
                          NULL, OPEN_EXISTING,
                          FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    free(lp);
    if (d->file == INVALID_HANDLE_VALUE) {
        FormatWin32Error(L"无法打开文件", GetLastError(), err, errcap);
        free(d);
        return NULL;
    }
    if (!GetFileSizeEx(d->file, &size) || size.QuadPart <= 0) {
        StringCchCopyW(err, errcap, L"解密失败：文件过小或无法读取");
        CloseHandle(d->file);
        free(d);
        return NULL;
    }
    d->file_size = (uint64_t)size.QuadPart;
    memset(header, 0, sizeof(header));
    {
        size_t probe = d->file_size < sizeof(header) ? (size_t)d->file_size : sizeof(header);
        if (!read_at(d->file, 0, header, probe, err, errcap)) {
            CloseHandle(d->file);
            free(d);
            return NULL;
        }
    }
    if (d->file_size < 16 || !AudioMagicOk(header, 16)) {
        StringCchPrintfW(err, errcap, L"不是有效的 %s 文件",
                         KindDisplayName(kind));
        CloseHandle(d->file);
        free(d);
        return NULL;
    }
    if (d->file_size < 1024) {
        StringCchCopyW(err, errcap, L"解密失败：文件过小");
        CloseHandle(d->file);
        free(d);
        return NULL;
    }
    audio_offset = rd_le32(header + 0x10);
    version = rd_le32(header + 0x14);
    if (audio_offset < 1024 || audio_offset >= d->file_size) {
        StringCchCopyW(err, errcap, L"解密失败：文件头损坏");
        CloseHandle(d->file);
        free(d);
        return NULL;
    }
    d->audio_offset = audio_offset;
    d->audio_size = d->file_size - audio_offset;
    d->version = version;

    if (version == 5) {
        if (!open_v5(d, header, cache, setting, err, errcap)) {
            CloseHandle(d->file);
            free(d);
            return NULL;
        }
    } else if (version == 3 || version == 4) {
        if (!open_v3(d, header, err, errcap)) {
            CloseHandle(d->file);
            free(d);
            return NULL;
        }
    } else {
        StringCchPrintfW(err, errcap, L"解密失败：未知加密版本（%lu）",
                         (unsigned long)version);
        CloseHandle(d->file);
        free(d);
        return NULL;
    }
    return d;
}

AudioDecryptor *AudioOpen(const wchar_t *path, KeyDbCache *keydb_cache,
                          const wchar_t *keydb_setting,
                          wchar_t *err, size_t errcap)
{
    return audio_open_impl(path, keydb_cache, keydb_setting, err, errcap);
}

uint64_t AudioSize(const AudioDecryptor *d)
{
    return d ? d->audio_size : 0;
}

uint64_t AudioOffset(const AudioDecryptor *d)
{
    return d ? d->audio_offset : 0;
}

uint32_t AudioVersion(const AudioDecryptor *d)
{
    return d ? d->version : 0;
}

bool AudioReadDecrypted(AudioDecryptor *d, uint64_t offset,
                        uint8_t *buf, size_t len,
                        wchar_t *err, size_t errcap)
{
    uint64_t i;

    if (!d) return false;
    if (offset > d->audio_size || len > d->audio_size - offset) {
        StringCchCopyW(err, errcap, L"解密失败：读取范围无效");
        return false;
    }
    if (!read_at(d->file, d->audio_offset + offset, buf, len, err, errcap)) {
        return false;
    }
    if (d->mode == DEC_QMC2) {
        qmc_decrypt(&d->qmc, buf, len, offset);
        return true;
    }
    for (i = 0; i < len; ++i) {
        uint64_t g = offset + i;
        uint32_t block = (uint32_t)(g >> 4);
        uint32_t col = (uint32_t)(g & 15);
        uint32_t phase;
        size_t own_idx;
        size_t mend_idx;
        uint8_t xmask;
        phase = block % 17u;
        own_idx = ((size_t)phase * 16u + col) % 17u;
        mend_idx = ((size_t)phase * 16u + col) % 272u;
        xmask = scramble_byte((uint8_t)(g_pubkey[block] ^ MEND_TABLE[mend_idx]));
        buf[i] = (uint8_t)(scramble_byte((uint8_t)(buf[i] ^ d->own_key[own_idx])) ^ xmask);
    }
    return true;
}

void AudioClose(AudioDecryptor *d)
{
    if (!d) return;
    if (d->file != INVALID_HANDLE_VALUE) CloseHandle(d->file);
    qmc_free(&d->qmc);
    free(d);
}

const wchar_t *SniffAudioExt(const uint8_t *buf, size_t len, bool *recognized)
{
    if (recognized) *recognized = true;
    if (!buf || len < 4) {
        if (recognized) *recognized = false;
        return L"mp3";
    }
    if (memcmp(buf, "ID3", 3) == 0) return L"mp3";
    if (memcmp(buf, "fLaC", 4) == 0) return L"flac";
    if (memcmp(buf, "OggS", 4) == 0) return L"ogg";
    if (memcmp(buf, "RIFF", 4) == 0) return L"wav";
    if (len >= 8 && memcmp(buf + 4, "ftyp", 4) == 0) return L"m4a";
    if (memcmp(buf, "MAC ", 4) == 0) return L"ape";
    if (memcmp(buf, "wvpk", 4) == 0) return L"wv";
    if (len >= 12 && memcmp(buf, "FORM", 4) == 0 &&
        (memcmp(buf + 8, "AIFF", 4) == 0 || memcmp(buf + 8, "AIFC", 4) == 0)) {
        return L"aiff";
    }
    if (memcmp(buf, "\x1A\x45\xDF\xA3", 4) == 0) return L"mka";
    if (len >= 16 && memcmp(buf, "\x30\x26\xB2\x75\x8E\x66\xCF\x11", 8) == 0) return L"wma";
    if (len >= 5 && memcmp(buf, "#!AMR", 5) == 0) return L"amr";
    if (memcmp(buf, "DSD ", 4) == 0) return L"dsf";
    if (memcmp(buf, "TTA1", 4) == 0) return L"tta";
    if (memcmp(buf, "MPCK", 4) == 0 || memcmp(buf, "MP+", 3) == 0) return L"mpc";
    if (buf[0] == 0xFF && (buf[1] & 0xE0) == 0xE0) {
        if ((buf[1] & 0x06) == 0x00) return L"aac";
        return L"mp3";
    }
    if (recognized) *recognized = false;
    return L"mp3";
}
