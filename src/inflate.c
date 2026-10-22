#include "inflate.h"
#include "util.h"
#include <strsafe.h>

#include <string.h>

#define MAXBITS 15
#define MAXLCODES 288
#define MAXDCODES 32
#define MAXCODES (MAXLCODES + MAXDCODES)

typedef struct {
    const uint8_t *in;
    size_t inlen;
    size_t inpos;
    uint32_t bitbuf;
    int bitcnt;
} BitReader;

typedef struct {
    unsigned short count[MAXBITS + 1];
    unsigned short symbol[MAXCODES];
} Huffman;

typedef struct {
    uint8_t *out;
    size_t len;
    size_t cap;
    size_t max;
} OutBuf;

static int br_bits(BitReader *br, int need, uint32_t *value)
{
    uint32_t val;
    while (br->bitcnt < need) {
        if (br->inpos >= br->inlen) return 0;
        br->bitbuf |= (uint32_t)br->in[br->inpos++] << br->bitcnt;
        br->bitcnt += 8;
    }
    val = br->bitbuf & ((1u << need) - 1u);
    br->bitbuf >>= need;
    br->bitcnt -= need;
    *value = val;
    return 1;
}

static void br_align(BitReader *br)
{
    br->bitbuf = 0;
    br->bitcnt = 0;
}

static int huff_build(Huffman *h, const uint8_t *lengths, int n)
{
    int len;
    int sym;
    int left;
    unsigned short offs[MAXBITS + 1];

    memset(h->count, 0, sizeof(h->count));
    for (sym = 0; sym < n; ++sym) {
        h->count[lengths[sym]]++;
    }
    if (h->count[0] == (unsigned short)n) return 0;

    left = 1;
    for (len = 1; len <= MAXBITS; ++len) {
        left <<= 1;
        left -= (int)h->count[len];
        if (left < 0) return -1;
    }

    offs[0] = 0;
    offs[1] = 0;
    for (len = 1; len < MAXBITS; ++len) {
        offs[len + 1] = (unsigned short)(offs[len] + h->count[len]);
    }
    for (sym = 0; sym < n; ++sym) {
        if (lengths[sym] != 0) {
            h->symbol[offs[lengths[sym]]++] = (unsigned short)sym;
        }
    }
    return 0;
}

static int huff_decode(BitReader *br, const Huffman *h)
{
    int code = 0;
    int first = 0;
    int index = 0;
    int len;
    for (len = 1; len <= MAXBITS; ++len) {
        uint32_t b;
        int count;
        if (!br_bits(br, 1, &b)) return -1;
        code |= (int)b;
        count = (int)h->count[len];
        if (code - first < count) {
            return (int)h->symbol[index + (code - first)];
        }
        index += count;
        first = (first + count) << 1;
        code <<= 1;
    }
    return -1;
}

static bool out_reserve(OutBuf *o, size_t extra)
{
    size_t need;
    size_t cap;
    uint8_t *p;

    if (extra > o->max - o->len) return false;
    need = o->len + extra;
    if (need <= o->cap) return true;
    cap = o->cap ? o->cap : 4096;
    while (cap < need) {
        if (cap > o->max / 2) {
            cap = o->max;
            break;
        }
        cap *= 2;
    }
    if (cap < need) cap = need;
    p = (uint8_t *)xrealloc(o->out, cap);
    if (!p) return false;
    o->out = p;
    o->cap = cap;
    return true;
}

static bool inflate_codes(BitReader *br, OutBuf *o, const Huffman *lit,
                          const Huffman *dist)
{
    static const unsigned short LBASE[29] = {
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
        35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258
    };
    static const unsigned char LEXTRA[29] = {
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
        3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0
    };
    static const unsigned short DBASE[30] = {
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
        257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577
    };
    static const unsigned char DEXTRA[30] = {
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
        7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13
    };

    for (;;) {
        int sym = huff_decode(br, lit);
        if (sym < 0) return false;
        if (sym < 256) {
            if (!out_reserve(o, 1)) return false;
            o->out[o->len++] = (uint8_t)sym;
        } else if (sym == 256) {
            return true;
        } else {
            int li = sym - 257;
            uint32_t extra = 0;
            size_t length;
            int dsym;
            size_t distance;
            size_t i;

            if (li < 0 || li >= 29) return false;
            if (LEXTRA[li] && !br_bits(br, LEXTRA[li], &extra)) return false;
            length = (size_t)LBASE[li] + extra;
            dsym = huff_decode(br, dist);
            if (dsym < 0 || dsym >= 30) return false;
            extra = 0;
            if (DEXTRA[dsym] && !br_bits(br, DEXTRA[dsym], &extra)) return false;
            distance = (size_t)DBASE[dsym] + extra;
            if (distance == 0 || distance > o->len) return false;
            if (!out_reserve(o, length)) return false;
            for (i = 0; i < length; ++i) {
                o->out[o->len] = o->out[o->len - distance];
                o->len++;
            }
        }
    }
}

static bool fixed_trees(Huffman *lit, Huffman *dist)
{
    uint8_t lengths[MAXLCODES];
    int i;
    for (i = 0; i < 144; ++i) lengths[i] = 8;
    for (i = 144; i < 256; ++i) lengths[i] = 9;
    for (i = 256; i < 280; ++i) lengths[i] = 7;
    for (i = 280; i < 288; ++i) lengths[i] = 8;
    if (huff_build(lit, lengths, 288) != 0) return false;
    for (i = 0; i < 32; ++i) lengths[i] = 5;
    if (huff_build(dist, lengths, 32) != 0) return false;
    return true;
}

static bool dynamic_trees(BitReader *br, Huffman *lit, Huffman *dist)
{
    static const unsigned char ORDER[19] = {
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
    };
    uint8_t lengths[MAXCODES];
    uint32_t v;
    int nlen;
    int ndist;
    int ncode;
    Huffman lencode;
    int i;

    if (!br_bits(br, 5, &v)) return false;
    nlen = (int)v + 257;
    if (!br_bits(br, 5, &v)) return false;
    ndist = (int)v + 1;
    if (!br_bits(br, 4, &v)) return false;
    ncode = (int)v + 4;
    if (nlen > MAXLCODES || ndist > MAXDCODES) return false;

    memset(lengths, 0, sizeof(lengths));
    for (i = 0; i < ncode; ++i) {
        if (!br_bits(br, 3, &v)) return false;
        lengths[ORDER[i]] = (uint8_t)v;
    }
    if (huff_build(&lencode, lengths, 19) != 0) return false;

    memset(lengths, 0, sizeof(lengths));
    i = 0;
    while (i < nlen + ndist) {
        int sym = huff_decode(br, &lencode);
        int rep;
        uint8_t value;
        if (sym < 0) return false;
        if (sym < 16) {
            lengths[i++] = (uint8_t)sym;
            continue;
        }
        if (sym == 16) {
            if (i == 0) return false;
            value = lengths[i - 1];
            if (!br_bits(br, 2, &v)) return false;
            rep = 3 + (int)v;
        } else if (sym == 17) {
            value = 0;
            if (!br_bits(br, 3, &v)) return false;
            rep = 3 + (int)v;
        } else if (sym == 18) {
            value = 0;
            if (!br_bits(br, 7, &v)) return false;
            rep = 11 + (int)v;
        } else {
            return false;
        }
        if (i + rep > nlen + ndist) return false;
        while (rep-- > 0) lengths[i++] = value;
    }
    if (lengths[256] == 0) return false;
    if (huff_build(lit, lengths, nlen) != 0) return false;
    if (huff_build(dist, lengths + nlen, ndist) != 0) return false;
    return true;
}

static bool inflate_raw(BitReader *br, OutBuf *o)
{
    int last = 0;
    while (!last) {
        uint32_t v;
        uint32_t type;
        if (!br_bits(br, 1, &v)) return false;
        last = (int)v;
        if (!br_bits(br, 2, &v)) return false;
        type = v;
        if (type == 0) {
            uint32_t len;
            uint32_t nlen;
            size_t i;
            br_align(br);
            if (!br_bits(br, 16, &len)) return false;
            if (!br_bits(br, 16, &nlen)) return false;
            if ((len ^ 0xFFFFu) != nlen) return false;
            if (!out_reserve(o, len)) return false;
            for (i = 0; i < len; ++i) {
                if (!br_bits(br, 8, &v)) return false;
                o->out[o->len++] = (uint8_t)v;
            }
        } else if (type == 1 || type == 2) {
            Huffman lit;
            Huffman dist;
            if (type == 1) {
                if (!fixed_trees(&lit, &dist)) return false;
            } else {
                if (!dynamic_trees(br, &lit, &dist)) return false;
            }
            if (!inflate_codes(br, o, &lit, &dist)) return false;
        } else {
            return false;
        }
    }
    return true;
}

static uint32_t adler32_compute(const uint8_t *data, size_t len)
{
    uint32_t a = 1;
    uint32_t b = 0;
    size_t i;
    for (i = 0; i < len; ++i) {
        a = (a + data[i]) % 65521u;
        b = (b + a) % 65521u;
    }
    return (b << 16) | a;
}

bool zlib_decompress(const uint8_t *in, size_t inlen, size_t max_out,
                     uint8_t **out, size_t *outlen,
                     wchar_t *err, size_t errcap)
{
    BitReader br;
    OutBuf o;
    uint32_t cmf;
    uint32_t flg;
    uint32_t adler = 0;
    uint32_t b;
    int i;

    *out = NULL;
    *outlen = 0;
    if (!in || inlen < 6) {
        StringCchCopyW(err, errcap, L"解压失败：数据不完整");
        return false;
    }
    cmf = in[0];
    flg = in[1];
    if ((cmf & 0x0F) != 8 || (cmf >> 4) > 7 ||
        ((cmf << 8) | flg) % 31 != 0 || (flg & 0x20)) {
        StringCchCopyW(err, errcap, L"解压失败：压缩头无效");
        return false;
    }
    memset(&br, 0, sizeof(br));
    br.in = in;
    br.inlen = inlen;
    br.inpos = 2;

    memset(&o, 0, sizeof(o));
    o.max = max_out;
    if (!inflate_raw(&br, &o)) {
        free(o.out);
        StringCchCopyW(err, errcap, L"解压失败：数据损坏");
        return false;
    }
    br_align(&br);
    for (i = 0; i < 4; ++i) {
        if (!br_bits(&br, 8, &b)) {
            free(o.out);
            StringCchCopyW(err, errcap, L"解压失败：数据不完整");
            return false;
        }
        adler = (adler << 8) | b;
    }
    if (adler != adler32_compute(o.out, o.len)) {
        free(o.out);
        StringCchCopyW(err, errcap, L"解压失败：校验值不符");
        return false;
    }
    *out = o.out;
    *outlen = o.len;
    return true;
}
