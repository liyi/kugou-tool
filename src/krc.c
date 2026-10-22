#include "krc.h"
#include "inflate.h"
#include "util.h"
#include <strsafe.h>

#include <string.h>
#include <stdio.h>

static const uint8_t KRC_XOR_KEY[16] = {
    0x40, 0x47, 0x61, 0x77, 0x5e, 0x32, 0x74, 0x47,
    0x51, 0x36, 0x31, 0x2d, 0xce, 0xd2, 0x6e, 0x69
};

bool KrcMagicOk(const uint8_t *data, size_t len)
{
    return data && len >= 4 && memcmp(data, "krc1", 4) == 0;
}

static bool is_digits_commas(const uint8_t *p, size_t n)
{
    bool has_comma = false;
    size_t i;
    for (i = 0; i < n; ++i) {
        if (p[i] == ',') {
            has_comma = true;
        } else if (p[i] < '0' || p[i] > '9') {
            return false;
        }
    }
    return has_comma;
}

static bool tag_name_keep(const uint8_t *name, size_t len, const char **canon)
{
    static const struct {
        const char *name;
        const char *canon;
    } tags[] = {
        { "ti", "ti" },
        { "ar", "ar" },
        { "al", "al" },
        { "by", "by" },
        { "offset", "offset" }
    };
    size_t i;
    for (i = 0; i < sizeof(tags) / sizeof(tags[0]); ++i) {
        size_t tlen = strlen(tags[i].name);
        if (len == tlen && _strnicmp((const char *)name, tags[i].name, tlen) == 0) {
            *canon = tags[i].canon;
            return true;
        }
    }
    return false;
}

static bool parse_start_ms(const uint8_t *p, size_t n, uint64_t *out)
{
    uint64_t v = 0;
    size_t i;
    bool any = false;
    for (i = 0; i < n; ++i) {
        if (p[i] == ',') break;
        if (p[i] < '0' || p[i] > '9') return false;
        if (v > (UINT64_MAX - (uint64_t)(p[i] - '0')) / 10ULL) return false;
        v = v * 10ULL + (uint64_t)(p[i] - '0');
        any = true;
    }
    if (!any) return false;
    *out = v;
    return true;
}

static bool append_timestamp(ByteBuf *b, uint64_t ms)
{
    uint64_t centis;
    uint64_t minutes;
    uint64_t seconds;
    uint64_t hundredths;
    char tmp[64];

    if (ms > UINT64_MAX - 5ULL) ms = UINT64_MAX - 5ULL;
    centis = (ms + 5ULL) / 10ULL;
    minutes = centis / 6000ULL;
    seconds = (centis / 100ULL) % 60ULL;
    hundredths = centis % 100ULL;
    snprintf(tmp, sizeof(tmp), "[%02llu:%02llu.%02llu]",
             (unsigned long long)minutes,
             (unsigned long long)seconds,
             (unsigned long long)hundredths);
    return BB_AppendStr(b, tmp);
}

static bool append_lyric_text(ByteBuf *b, const uint8_t *p, size_t n)
{
    size_t i = 0;
    while (i < n) {
        if (p[i] == '<') {
            size_t j = i + 1;
            while (j < n && p[j] != '>') ++j;
            if (j < n && is_digits_commas(p + i + 1, j - i - 1)) {
                i = j + 1;
                continue;
            }
        }
        if (!BB_AppendByte(b, p[i])) return false;
        ++i;
    }
    return true;
}

static bool build_lrc_utf8(const uint8_t *text, size_t len, ByteBuf *out,
                           wchar_t *err, size_t errcap)
{
    size_t pos = 0;

    if (len >= 3 && text[0] == 0xEF && text[1] == 0xBB && text[2] == 0xBF) {
        pos = 3;
    }

    while (pos < len) {
        size_t start = pos;
        size_t end;
        const uint8_t *line;
        size_t line_len;
        size_t close;
        size_t open;

        while (pos < len && text[pos] != '\n' && text[pos] != '\r') ++pos;
        end = pos;
        while (pos < len && (text[pos] == '\n' || text[pos] == '\r')) ++pos;
        line = text + start;
        line_len = end - start;
        while (line_len > 0 && line[line_len - 1] == ' ') {
            size_t k;
            bool only_ws = true;
            for (k = 0; k < line_len; ++k) {
                if (line[k] != ' ' && line[k] != '\t') {
                    only_ws = false;
                    break;
                }
            }
            if (only_ws) {
                line_len = 0;
            }
            break;
        }
        if (line_len == 0) continue;
        if (line[0] != '[') continue;
        open = 0;
        close = 1;
        while (close < line_len && line[close] != ']') ++close;
        if (close >= line_len) continue;

        if (is_digits_commas(line + open + 1, close - open - 1)) {
            uint64_t start_ms;
            if (!parse_start_ms(line + open + 1, close - open - 1, &start_ms)) {
                continue;
            }
            if (!append_timestamp(out, start_ms)) goto oom;
            if (!append_lyric_text(out, line + close + 1, line_len - close - 1)) goto oom;
            if (!BB_AppendStr(out, "\r\n")) goto oom;
        } else {
            size_t colon = 1;
            const char *canon = NULL;
            while (colon < close && line[colon] != ':') ++colon;
            if (colon >= close) continue;
            if (!tag_name_keep(line + 1, colon - 1, &canon)) continue;
            if (!BB_AppendByte(out, '[')) goto oom;
            if (!BB_AppendStr(out, canon)) goto oom;
            if (!BB_AppendByte(out, ':')) goto oom;
            if (!BB_Append(out, line + colon + 1, close - colon - 1)) goto oom;
            if (!BB_AppendStr(out, "]\r\n")) goto oom;
        }
    }
    return true;

oom:
    StringCchCopyW(err, errcap, L"内存不足");
    return false;
}

bool KrcToLrc(const uint8_t *data, size_t len, LrcEncoding enc,
              uint8_t **out, size_t *outlen, wchar_t *err, size_t errcap)
{
    uint8_t *xored = NULL;
    size_t xlen;
    uint8_t *plain = NULL;
    size_t plen = 0;
    ByteBuf lrc;
    bool ok = false;

    *out = NULL;
    *outlen = 0;
    err[0] = L'\0';
    if (!KrcMagicOk(data, len)) {
        StringCchCopyW(err, errcap, L"不是有效的 KRC 文件");
        return false;
    }
    if (len <= 4) {
        StringCchCopyW(err, errcap, L"解密失败：文件损坏");
        return false;
    }
    xlen = len - 4;
    xored = (uint8_t *)xmalloc(xlen);
    if (!xored) {
        StringCchCopyW(err, errcap, L"内存不足");
        return false;
    }
    {
        size_t i;
        for (i = 0; i < xlen; ++i) {
            xored[i] = data[4 + i] ^ KRC_XOR_KEY[i % KRC_KEY_SIZE];
        }
    }
    if (!zlib_decompress(xored, xlen, 64ULL * 1024ULL * 1024ULL,
                         &plain, &plen, err, errcap)) {
        free(xored);
        return false;
    }
    free(xored);

    BB_Init(&lrc);
    if (!build_lrc_utf8(plain, plen, &lrc, err, errcap)) {
        free(plain);
        BB_Free(&lrc);
        return false;
    }
    free(plain);

    if (enc == ENC_GBK) {
        wchar_t *wide = Utf8ToWideN((const char *)lrc.data, lrc.len);
        char *gbk;
        if (!wide) {
            StringCchCopyW(err, errcap, L"编码转换失败");
            BB_Free(&lrc);
            return false;
        }
        gbk = WideToCodepage(wide, 936);
        free(wide);
        if (!gbk) {
            StringCchCopyW(err, errcap, L"编码转换失败（GBK）");
            BB_Free(&lrc);
            return false;
        }
        *out = (uint8_t *)gbk;
        *outlen = strlen(gbk);
        ok = true;
    } else {
        size_t prefix = (enc == ENC_UTF8_BOM) ? 3 : 0;
        uint8_t *buf = (uint8_t *)xmalloc(lrc.len + prefix + 1);
        if (!buf) {
            StringCchCopyW(err, errcap, L"内存不足");
            BB_Free(&lrc);
            return false;
        }
        if (prefix) {
            buf[0] = 0xEF;
            buf[1] = 0xBB;
            buf[2] = 0xBF;
        }
        memcpy(buf + prefix, lrc.data, lrc.len);
        buf[prefix + lrc.len] = 0;
        *out = buf;
        *outlen = prefix + lrc.len;
        ok = true;
    }
    BB_Free(&lrc);
    return ok;
}
