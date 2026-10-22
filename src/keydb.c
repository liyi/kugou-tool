#include "keydb.h"
#include "crypto.h"
#include "util.h"
#include <strsafe.h>

#include <string.h>
#include <stdlib.h>

#define KEYDB_PAGE_SIZE 1024u
#define KEYDB_MAX_PAYLOAD (16u * 1024u * 1024u)
#define KEYDB_MAX_VALUES 128
#define KEYDB_MAX_DEPTH 64

typedef struct {
    char *id;
    char *ekey;
} KeyEntry;

struct KeyDb {
    HANDLE file;
    uint64_t file_size;
    bool encrypted;
    uint32_t page_size;
    uint32_t usable_size;
    uint32_t page_count;
    KeyEntry *entries;
    size_t entry_count;
    size_t entry_cap;
};

struct KeyDbCache {
    wchar_t *setting;
    KeyDb *db;
    wchar_t error[ERR_CAP];
    bool attempted;
    bool failed;
};

typedef struct {
    uint64_t serial;
    int64_t i64;
    const uint8_t *data;
    size_t len;
    bool is_int;
    bool is_text;
} SqlValue;

static uint16_t be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void derive_page_key_iv(uint32_t page_no, uint8_t key[16], uint8_t iv[16])
{
    static const uint8_t master[16] = {
        0x1d, 0x61, 0x31, 0x45, 0xb2, 0x47, 0xbf, 0x7f,
        0x3d, 0x18, 0x96, 0x72, 0x14, 0x4f, 0xe4, 0xbf
    };
    uint8_t buf[24];
    uint32_t ebx;
    int i;

    memset(buf, 0, sizeof(buf));
    memcpy(buf, master, 16);
    put_le32(buf + 16, page_no);
    put_le32(buf + 20, 0x546C4173u);
    md5_hash(buf, 24, key);

    memset(buf, 0, sizeof(buf));
    ebx = page_no + 1u;
    for (i = 0; i < 16; i += 4) {
        uint32_t eax = 0x7FFFFF07u * (ebx / 0xCE26u);
        uint32_t ecx = 0x9EF4u * ebx - eax;
        if (ecx & 0x80000000u) ecx += 0x7FFFFF07u;
        ebx = ecx;
        put_le32(buf + i, ebx);
    }
    md5_hash(buf, 16, iv);
}

static bool decrypt_page(KeyDb *db, uint32_t page_no, uint8_t *data,
                         wchar_t *err, size_t errcap)
{
    Aes128Dec aes;
    uint8_t key[16];
    uint8_t iv[16];

    derive_page_key_iv(page_no, key, iv);
    aes128_dec_init(&aes, key);
    if (page_no == 1) {
        uint8_t backup[8];
        memcpy(backup, data + 0x10, 8);
        memcpy(data + 0x10, data + 0x08, 8);
        aes128_cbc_decrypt(&aes, iv, data + 0x10, db->page_size - 0x10);
        if (memcmp(data + 0x10, backup, 8) != 0) {
            StringCchCopyW(err, errcap, L"需要密钥库：校验失败（可能是未知版本）");
            return false;
        }
        memcpy(data, "SQLite format 3\0", 16);
    } else {
        aes128_cbc_decrypt(&aes, iv, data, db->page_size);
    }
    return true;
}

static bool read_page(KeyDb *db, uint32_t page_no, uint8_t **out,
                      wchar_t *err, size_t errcap)
{
    uint8_t *buf;
    LARGE_INTEGER off;
    DWORD got = 0;

    *out = NULL;
    if (page_no < 1 || page_no > db->page_count) {
        StringCchCopyW(err, errcap, L"密钥库页面编号无效");
        return false;
    }
    buf = (uint8_t *)xmalloc(db->page_size);
    if (!buf) {
        StringCchCopyW(err, errcap, L"内存不足");
        return false;
    }
    off.QuadPart = (LONGLONG)((uint64_t)(page_no - 1) * db->page_size);
    if (!SetFilePointerEx(db->file, off, NULL, FILE_BEGIN) ||
        !ReadFile(db->file, buf, db->page_size, &got, NULL) ||
        got != db->page_size) {
        StringCchCopyW(err, errcap, L"密钥库读取失败");
        free(buf);
        return false;
    }
    if (db->encrypted) {
        if (!decrypt_page(db, page_no, buf, err, errcap)) {
            free(buf);
            return false;
        }
    }
    *out = buf;
    return true;
}

static bool read_varint(const uint8_t *p, size_t maxlen, uint64_t *out, size_t *used)
{
    uint64_t v = 0;
    size_t i;
    for (i = 0; i < 9; ++i) {
        uint8_t b;
        if (i >= maxlen) return false;
        b = p[i];
        if (i == 8) {
            v = (v << 8) | (uint64_t)b;
            *out = v;
            *used = 9;
            return true;
        }
        v = (v << 7) | (uint64_t)(b & 0x7F);
        if ((b & 0x80) == 0) {
            *out = v;
            *used = i + 1;
            return true;
        }
    }
    return false;
}

static bool read_cell_payload(KeyDb *db, const uint8_t *page, size_t cell_off,
                              uint8_t **payload, size_t *payload_len,
                              wchar_t *err, size_t errcap)
{
    uint64_t plen64;
    uint64_t rowid64;
    size_t used1;
    size_t used2;
    size_t plen;
    size_t local;
    size_t hdr_len;
    uint8_t *buf;
    size_t copied;

    *payload = NULL;
    *payload_len = 0;
    if (cell_off >= db->usable_size) {
        StringCchCopyW(err, errcap, L"密钥库数据损坏（单元格越界）");
        return false;
    }
    if (!read_varint(page + cell_off, db->usable_size - cell_off, &plen64, &used1)) {
        StringCchCopyW(err, errcap, L"密钥库数据损坏（长度字段）");
        return false;
    }
    if (cell_off + used1 > db->usable_size ||
        !read_varint(page + cell_off + used1, db->usable_size - cell_off - used1,
                     &rowid64, &used2)) {
        StringCchCopyW(err, errcap, L"密钥库数据损坏（行编号）");
        return false;
    }
    (void)rowid64;
    hdr_len = used1 + used2;
    if (plen64 > KEYDB_MAX_PAYLOAD) {
        StringCchCopyW(err, errcap, L"密钥库记录过大");
        return false;
    }
    plen = (size_t)plen64;
    if (plen == 0) {
        StringCchCopyW(err, errcap, L"密钥库数据损坏（空记录）");
        return false;
    }
    if (plen <= db->usable_size - 35u) {
        local = plen;
    } else {
        size_t max_local = ((db->usable_size - 12u) * 32u / 255u) - 23u;
        size_t k = max_local + ((plen - max_local) % (db->usable_size - 4u));
        local = (k <= db->usable_size - 35u) ? k : max_local;
    }
    if (cell_off + hdr_len + local > db->usable_size) {
        StringCchCopyW(err, errcap, L"密钥库数据损坏（记录越界）");
        return false;
    }
    buf = (uint8_t *)xmalloc(plen);
    if (!buf) {
        StringCchCopyW(err, errcap, L"内存不足");
        return false;
    }
    memcpy(buf, page + cell_off + hdr_len, local);
    copied = local;
    if (copied < plen) {
        uint32_t ov;
        size_t guard = 0;
        if (cell_off + hdr_len + local + 4 > db->usable_size) {
            free(buf);
            StringCchCopyW(err, errcap, L"密钥库数据损坏（溢出指针）");
            return false;
        }
        ov = be32(page + cell_off + hdr_len + local);
        while (copied < plen) {
            uint8_t *opage = NULL;
            size_t chunk;
            size_t next;
            if (guard++ > db->page_count || ov == 0) {
                free(buf);
                StringCchCopyW(err, errcap, L"密钥库数据损坏（溢出链）");
                return false;
            }
            if (!read_page(db, ov, &opage, err, errcap)) {
                free(buf);
                return false;
            }
            chunk = plen - copied;
            if (chunk > db->usable_size - 4u) chunk = db->usable_size - 4u;
            memcpy(buf + copied, opage + 4, chunk);
            copied += chunk;
            next = be32(opage);
            free(opage);
            ov = (uint32_t)next;
        }
    }
    *payload = buf;
    *payload_len = plen;
    return true;
}

static bool parse_record(const uint8_t *payload, size_t len,
                         SqlValue *vals, size_t max_vals, size_t *nvals,
                         wchar_t *err, size_t errcap)
{
    uint64_t hdr_size64;
    size_t used;
    size_t hdr_end;
    size_t pos;
    size_t body;
    size_t count = 0;

    *nvals = 0;
    if (!read_varint(payload, len, &hdr_size64, &used)) {
        StringCchCopyW(err, errcap, L"密钥库数据损坏（记录头）");
        return false;
    }
    if (hdr_size64 < used || hdr_size64 > len) {
        StringCchCopyW(err, errcap, L"密钥库数据损坏（记录头长度）");
        return false;
    }
    hdr_end = (size_t)hdr_size64;
    pos = used;
    body = hdr_end;
    while (pos < hdr_end) {
        uint64_t serial;
        size_t n;
        size_t blen = 0;
        SqlValue *v;
        if (!read_varint(payload + pos, hdr_end - pos, &serial, &n)) {
            StringCchCopyW(err, errcap, L"密钥库数据损坏（字段类型）");
            return false;
        }
        pos += n;
        if (count >= max_vals) {
            StringCchCopyW(err, errcap, L"密钥库记录字段过多");
            return false;
        }
        v = &vals[count];
        memset(v, 0, sizeof(*v));
        v->serial = serial;
        if (serial == 0) {
            blen = 0;
        } else if (serial >= 1 && serial <= 6) {
            blen = (size_t)serial;
        } else if (serial == 7) {
            blen = 8;
        } else if (serial == 8 || serial == 9) {
            blen = 0;
        } else if (serial == 10 || serial == 11) {
            StringCchCopyW(err, errcap, L"密钥库数据损坏（字段类型 10/11）");
            return false;
        } else {
            blen = (size_t)((serial - 12) / 2);
            if ((serial & 1) != 0) {
                blen = (size_t)((serial - 13) / 2);
                v->is_text = true;
            }
        }
        if (body > len || blen > len - body) {
            StringCchCopyW(err, errcap, L"密钥库数据损坏（字段越界）");
            return false;
        }
        v->data = payload + body;
        v->len = blen;
        if (serial >= 1 && serial <= 6) {
            int64_t value = 0;
            size_t i;
            bool neg;
            for (i = 0; i < blen; ++i) value = (value << 8) | (int64_t)v->data[i];
            neg = (v->data[0] & 0x80) != 0;
            if (neg) {
                for (i = blen; i < 8; ++i) value |= (int64_t)((uint64_t)0xFFu << (i * 8));
            }
            v->i64 = value;
            v->is_int = true;
        } else if (serial == 8) {
            v->i64 = 0;
            v->is_int = true;
        } else if (serial == 9) {
            v->i64 = 1;
            v->is_int = true;
        }
        body += blen;
        ++count;
    }
    *nvals = count;
    return true;
}

typedef bool (*CellVisitor)(KeyDb *db, const uint8_t *page, uint32_t page_no,
                            size_t cell_off, void *ctx,
                            wchar_t *err, size_t errcap);

static bool walk_table(KeyDb *db, uint32_t page_no, CellVisitor visitor,
                       void *ctx, int depth, wchar_t *err, size_t errcap)
{
    uint8_t *page = NULL;
    uint8_t type;
    size_t hdr;
    uint16_t ncell;
    size_t ptr;
    size_t i;

    if (depth > KEYDB_MAX_DEPTH) {
        StringCchCopyW(err, errcap, L"密钥库索引层级过深");
        return false;
    }
    if (!read_page(db, page_no, &page, err, errcap)) return false;
    hdr = (page_no == 1) ? 100u : 0u;
    if (db->page_size < hdr + 12u) {
        free(page);
        StringCchCopyW(err, errcap, L"密钥库页面无效");
        return false;
    }
    type = page[hdr];
    ncell = be16(page + hdr + 3);
    if (type == 0x0D) {
        ptr = hdr + 8u;
    } else if (type == 0x05) {
        ptr = hdr + 12u;
    } else {
        free(page);
        StringCchCopyW(err, errcap, L"密钥库索引类型不受支持");
        return false;
    }
    if (ptr + (size_t)ncell * 2u > db->usable_size) {
        free(page);
        StringCchCopyW(err, errcap, L"密钥库数据损坏（单元格数组）");
        return false;
    }
    if (type == 0x0D) {
        for (i = 0; i < ncell; ++i) {
            size_t off = be16(page + ptr + i * 2u);
            if (off >= db->usable_size) {
                free(page);
                StringCchCopyW(err, errcap, L"密钥库数据损坏（单元格偏移）");
                return false;
            }
            if (!visitor(db, page, page_no, off, ctx, err, errcap)) {
                free(page);
                return false;
            }
        }
    } else {
        for (i = 0; i < ncell; ++i) {
            size_t off = be16(page + ptr + i * 2u);
            uint32_t child;
            if (off + 4 > db->usable_size) {
                free(page);
                StringCchCopyW(err, errcap, L"密钥库数据损坏（子页指针）");
                return false;
            }
            child = be32(page + off);
            if (!walk_table(db, child, visitor, ctx, depth + 1, err, errcap)) {
                free(page);
                return false;
            }
        }
        {
            uint32_t right = be32(page + hdr + 8u);
            if (!walk_table(db, right, visitor, ctx, depth + 1, err, errcap)) {
                free(page);
                return false;
            }
        }
    }
    free(page);
    return true;
}

static bool value_equals_text(const SqlValue *v, const char *text)
{
    size_t n = strlen(text);
    if (!v->is_text || v->len != n) return false;
    return _strnicmp((const char *)v->data, text, (int)n) == 0;
}

static bool value_copy_text(const SqlValue *v, char **out)
{
    char *s;
    if (!v->is_text) return false;
    s = (char *)xmalloc(v->len + 1);
    if (!s) return false;
    memcpy(s, v->data, v->len);
    s[v->len] = '\0';
    *out = s;
    return true;
}

typedef struct {
    uint32_t root_page;
    char *sql;
    bool found;
} SchemaCtx;

static bool schema_visitor(KeyDb *db, const uint8_t *page, uint32_t page_no,
                           size_t cell_off, void *ctx,
                           wchar_t *err, size_t errcap)
{
    SchemaCtx *sc = (SchemaCtx *)ctx;
    uint8_t *payload = NULL;
    size_t plen = 0;
    SqlValue vals[KEYDB_MAX_VALUES];
    size_t nvals = 0;
    bool ok = true;
    (void)db;
    (void)page_no;

    if (sc->found) return true;
    if (!read_cell_payload(db, page, cell_off, &payload, &plen, err, errcap)) {
        return false;
    }
    if (!parse_record(payload, plen, vals, KEYDB_MAX_VALUES, &nvals, err, errcap)) {
        free(payload);
        return false;
    }
    if (nvals >= 5 &&
        value_equals_text(&vals[0], "table") &&
        value_equals_text(&vals[1], "ShareFileItems") &&
        vals[3].is_int && vals[3].i64 > 0 &&
        vals[3].i64 <= (int64_t)db->page_count) {
        sc->root_page = (uint32_t)vals[3].i64;
        ok = value_copy_text(&vals[4], &sc->sql);
        sc->found = ok;
    }
    free(payload);
    return ok;
}

static bool find_schema_root(KeyDb *db, uint32_t *root_page, char **sql,
                             wchar_t *err, size_t errcap)
{
    SchemaCtx sc;
    memset(&sc, 0, sizeof(sc));
    if (!walk_table(db, 1, schema_visitor, &sc, 0, err, errcap)) {
        free(sc.sql);
        return false;
    }
    if (!sc.found || !sc.sql || sc.root_page == 0) {
        free(sc.sql);
        StringCchCopyW(err, errcap, L"密钥库中未找到 ShareFileItems 表");
        return false;
    }
    *root_page = sc.root_page;
    *sql = sc.sql;
    return true;
}

static void trim_ascii(const char **s, size_t *len)
{
    while (*len > 0 && (**s == ' ' || **s == '\t' || **s == '\r' || **s == '\n')) {
        ++*s;
        --*len;
    }
    while (*len > 0) {
        char c = (*s)[*len - 1];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            --*len;
        } else {
            break;
        }
    }
}

static bool ident_equals(const char *s, size_t len, const char *want)
{
    size_t n = strlen(want);
    return len == n && _strnicmp(s, want, (int)n) == 0;
}

static bool parse_column_indices(const char *sql, size_t sql_len,
                                 int *keyid_idx, int *ekey_idx,
                                 wchar_t *err, size_t errcap)
{
    size_t i;
    size_t seg_start;
    int depth = 0;
    char quote = 0;
    int col = 0;
    bool have_id = false;
    bool have_key = false;

    *keyid_idx = -1;
    *ekey_idx = -1;
    i = 0;
    while (i < sql_len && sql[i] != '(') ++i;
    if (i >= sql_len) {
        StringCchCopyW(err, errcap, L"密钥库表结构无效");
        return false;
    }
    ++i;
    seg_start = i;
    for (; i < sql_len; ++i) {
        char c = sql[i];
        if (quote) {
            if (c == quote) {
                if (quote != ']' && i + 1 < sql_len && sql[i + 1] == quote) {
                    ++i;
                } else {
                    quote = 0;
                }
            }
            continue;
        }
        if (c == '"' || c == '\'' || c == '`') {
            quote = c;
            continue;
        }
        if (c == '[') {
            quote = ']';
            continue;
        }
        if (c == '(') {
            ++depth;
            continue;
        }
        if (c == ')') {
            if (depth == 0) {
                /* process final segment below */
            } else {
                --depth;
                continue;
            }
        }
        if (depth != 0) continue;
        if (c != ',' && c != ')') continue;

        {
            const char *seg = sql + seg_start;
            size_t seg_len = i - seg_start;
            const char *p;
            size_t n;
            bool constraint = false;
            trim_ascii(&seg, &seg_len);
            if (seg_len == 0) {
                seg_start = i + 1;
                if (c == ')') break;
                continue;
            }
            if (*seg == '"' || *seg == '\'' || *seg == '`' || *seg == '[') {
                char close = (*seg == '[') ? ']' : *seg;
                p = seg + 1;
                n = 0;
                while (n < seg_len - 1 && p[n] != close) ++n;
            } else {
                p = seg;
                n = 0;
                while (n < seg_len &&
                       ((p[n] >= 'a' && p[n] <= 'z') || (p[n] >= 'A' && p[n] <= 'Z') ||
                        (p[n] >= '0' && p[n] <= '9') || p[n] == '_')) {
                    ++n;
                }
                if (ident_equals(p, n, "CONSTRAINT") ||
                    ident_equals(p, n, "PRIMARY") ||
                    ident_equals(p, n, "UNIQUE") ||
                    ident_equals(p, n, "CHECK") ||
                    ident_equals(p, n, "FOREIGN")) {
                    constraint = true;
                }
            }
            if (!constraint) {
                if (ident_equals(p, n, "EncryptionKeyId")) {
                    *keyid_idx = col;
                    have_id = true;
                } else if (ident_equals(p, n, "EncryptionKey")) {
                    *ekey_idx = col;
                    have_key = true;
                }
                ++col;
            }
        }
        seg_start = i + 1;
        if (c == ')') break;
    }
    if (!have_id || !have_key) {
        StringCchCopyW(err, errcap, L"密钥库表缺少密钥字段");
        return false;
    }
    return true;
}

typedef struct {
    int keyid_idx;
    int ekey_idx;
    KeyDb *db;
} DataCtx;

static bool add_entry(KeyDb *db, const char *id, const char *ekey)
{
    size_t i;
    for (i = 0; i < db->entry_count; ++i) {
        if (_stricmp(db->entries[i].id, id) == 0) return true;
    }
    if (db->entry_count == db->entry_cap) {
        size_t cap = db->entry_cap ? db->entry_cap * 2 : 16;
        KeyEntry *p = (KeyEntry *)xrealloc(db->entries, cap * sizeof(KeyEntry));
        if (!p) return false;
        db->entries = p;
        db->entry_cap = cap;
    }
    db->entries[db->entry_count].id = xstrdup(id);
    db->entries[db->entry_count].ekey = xstrdup(ekey);
    if (!db->entries[db->entry_count].id || !db->entries[db->entry_count].ekey) {
        free(db->entries[db->entry_count].id);
        free(db->entries[db->entry_count].ekey);
        return false;
    }
    ++db->entry_count;
    return true;
}

static bool data_visitor(KeyDb *db, const uint8_t *page, uint32_t page_no,
                         size_t cell_off, void *ctx,
                         wchar_t *err, size_t errcap)
{
    DataCtx *dc = (DataCtx *)ctx;
    uint8_t *payload = NULL;
    size_t plen = 0;
    SqlValue vals[KEYDB_MAX_VALUES];
    size_t nvals = 0;
    bool ok = true;
    (void)page_no;

    if (!read_cell_payload(db, page, cell_off, &payload, &plen, err, errcap)) {
        return false;
    }
    if (!parse_record(payload, plen, vals, KEYDB_MAX_VALUES, &nvals, err, errcap)) {
        free(payload);
        return false;
    }
    if (dc->keyid_idx >= 0 && dc->ekey_idx >= 0 &&
        (size_t)dc->keyid_idx < nvals && (size_t)dc->ekey_idx < nvals) {
        SqlValue *id = &vals[dc->keyid_idx];
        SqlValue *ekey = &vals[dc->ekey_idx];
        if (id->len > 0 && id->len <= 256 && ekey->len > 0 && ekey->len <= 16384) {
            char *sid = NULL;
            char *skey = NULL;
            if (!value_copy_text(id, &sid) || !value_copy_text(ekey, &skey)) {
                free(sid);
                free(skey);
                free(payload);
                StringCchCopyW(err, errcap, L"内存不足");
                return false;
            }
            if (!skey[0] || !add_entry(db, sid, skey)) {
                free(sid);
                free(skey);
                free(payload);
                StringCchCopyW(err, errcap, L"内存不足");
                return false;
            }
            free(sid);
            free(skey);
        }
    }
    free(payload);
    return ok;
}

static KeyDb *db_open(const wchar_t *path, wchar_t *err, size_t errcap)
{
    KeyDb *db;
    wchar_t *lp;
    LARGE_INTEGER size;
    uint8_t probe[KEYDB_PAGE_SIZE];
    DWORD got = 0;
    uint32_t root_page = 0;
    char *sql = NULL;
    DataCtx dc;
    int keyid_idx;
    int ekey_idx;

    db = (KeyDb *)xcalloc(1, sizeof(KeyDb));
    if (!db) {
        StringCchCopyW(err, errcap, L"内存不足");
        return NULL;
    }
    db->file = INVALID_HANDLE_VALUE;
    lp = MakeLongPath(path);
    if (!lp) {
        StringCchCopyW(err, errcap, L"内存不足");
        free(db);
        return NULL;
    }
    db->file = CreateFileW(lp, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    free(lp);
    if (db->file == INVALID_HANDLE_VALUE) {
        FormatWin32Error(L"需要密钥库：无法打开文件", GetLastError(), err, errcap);
        free(db);
        return NULL;
    }
    if (!GetFileSizeEx(db->file, &size) || size.QuadPart <= 0) {
        FormatWin32Error(L"需要密钥库：无法读取文件大小", GetLastError(), err, errcap);
        CloseHandle(db->file);
        free(db);
        return NULL;
    }
    db->file_size = (uint64_t)size.QuadPart;

    if (!SetFilePointerEx(db->file, (LARGE_INTEGER){0}, NULL, FILE_BEGIN) ||
        !ReadFile(db->file, probe, KEYDB_PAGE_SIZE, &got, NULL) ||
        got != KEYDB_PAGE_SIZE) {
        StringCchCopyW(err, errcap, L"需要密钥库：文件不完整");
        CloseHandle(db->file);
        free(db);
        return NULL;
    }

    if (memcmp(probe, "SQLite format 3\0", 16) == 0) {
        uint32_t page_size = be16(probe + 16);
        uint32_t reserved = probe[20];
        if (page_size < 512 || page_size > 32768 ||
            (page_size & (page_size - 1)) != 0 || reserved >= page_size) {
            StringCchCopyW(err, errcap, L"需要密钥库：页面大小无效");
            CloseHandle(db->file);
            free(db);
            return NULL;
        }
        if (db->file_size % page_size != 0) {
            StringCchCopyW(err, errcap, L"需要密钥库：文件大小无效");
            CloseHandle(db->file);
            free(db);
            return NULL;
        }
        db->encrypted = false;
        db->page_size = page_size;
        db->usable_size = page_size - reserved;
        db->page_count = (uint32_t)(db->file_size / page_size);
    } else {
        uint8_t *p1 = NULL;
        if (db->file_size % KEYDB_PAGE_SIZE != 0 ||
            be16(probe + 0x10) != KEYDB_PAGE_SIZE ||
            probe[0x14] != 0x00 || probe[0x15] != 0x40 ||
            probe[0x16] != 0x20 || probe[0x17] != 0x20) {
            StringCchCopyW(err, errcap, L"需要密钥库：格式不受支持");
            CloseHandle(db->file);
            free(db);
            return NULL;
        }
        db->encrypted = true;
        db->page_size = KEYDB_PAGE_SIZE;
        db->usable_size = KEYDB_PAGE_SIZE;
        db->page_count = (uint32_t)(db->file_size / KEYDB_PAGE_SIZE);
        if (!read_page(db, 1, &p1, err, errcap)) {
            CloseHandle(db->file);
            free(db);
            return NULL;
        }
        {
            uint32_t page_size = be16(p1 + 16);
            uint32_t reserved = p1[20];
            if (page_size != KEYDB_PAGE_SIZE || reserved >= page_size) {
                free(p1);
                StringCchCopyW(err, errcap, L"需要密钥库：页面大小不受支持");
                CloseHandle(db->file);
                free(db);
                return NULL;
            }
            db->usable_size = page_size - reserved;
        }
        free(p1);
    }

    if (!find_schema_root(db, &root_page, &sql, err, errcap)) {
        CloseHandle(db->file);
        free(db);
        return NULL;
    }
    if (!parse_column_indices(sql, strlen(sql), &keyid_idx, &ekey_idx, err, errcap)) {
        free(sql);
        CloseHandle(db->file);
        free(db);
        return NULL;
    }
    dc.keyid_idx = keyid_idx;
    dc.ekey_idx = ekey_idx;
    dc.db = db;
    free(sql);
    if (!walk_table(db, root_page, data_visitor, &dc, 0, err, errcap)) {
        CloseHandle(db->file);
        {
            size_t i;
            for (i = 0; i < db->entry_count; ++i) {
                free(db->entries[i].id);
                free(db->entries[i].ekey);
            }
        }
        free(db->entries);
        free(db);
        return NULL;
    }
    return db;
}

static void db_close(KeyDb *db)
{
    size_t i;
    if (!db) return;
    if (db->file != INVALID_HANDLE_VALUE) CloseHandle(db->file);
    for (i = 0; i < db->entry_count; ++i) {
        free(db->entries[i].id);
        free(db->entries[i].ekey);
    }
    free(db->entries);
    free(db);
}

static const char *db_lookup(KeyDb *db, const char *hash)
{
    size_t i;
    if (!db || !hash) return NULL;
    for (i = 0; i < db->entry_count; ++i) {
        if (_stricmp(db->entries[i].id, hash) == 0) {
            return db->entries[i].ekey;
        }
    }
    return NULL;
}

static bool path_in_dir(const wchar_t *dir, const wchar_t *sub, wchar_t **found)
{
    wchar_t *p = JoinPath(dir, sub);
    bool ok = false;
    if (!p) return false;
    if (FileExistsW(p) && !IsDirectoryW(p)) {
        *found = p;
        ok = true;
    } else {
        free(p);
    }
    return ok;
}

static wchar_t *find_in_dir(const wchar_t *dir)
{
    static const wchar_t *subs[] = {
        L"KGMusicV3.db",
        L"KuGou8\\KGMusicV3.db",
        L"Kugou8\\KGMusicV3.db",
        L"KuGou\\KGMusicV3.db",
        L"Kugou\\KGMusicV3.db",
        L"Data\\KGMusicV3.db",
        L"KuGou\\KGMusicV3.db"
    };
    size_t i;
    for (i = 0; i < sizeof(subs) / sizeof(subs[0]); ++i) {
        wchar_t *found = NULL;
        if (path_in_dir(dir, subs[i], &found)) return found;
    }
    return NULL;
}

static wchar_t *env_dup(const wchar_t *name)
{
    DWORD n = GetEnvironmentVariableW(name, NULL, 0);
    wchar_t *buf;
    if (n == 0) return NULL;
    buf = (wchar_t *)xmalloc((size_t)n * sizeof(wchar_t));
    if (!buf) return NULL;
    if (GetEnvironmentVariableW(name, buf, n) == 0) {
        free(buf);
        return NULL;
    }
    return buf;
}

wchar_t *KeyDb_AutoDetect(void)
{
    static const wchar_t *envs[] = {
        L"APPDATA", L"LOCALAPPDATA", L"PROGRAMDATA"
    };
    size_t i;
    wchar_t *found = NULL;
    wchar_t *exe = NULL;

    for (i = 0; i < sizeof(envs) / sizeof(envs[0]); ++i) {
        wchar_t *base = env_dup(envs[i]);
        if (base) {
            found = find_in_dir(base);
            free(base);
            if (found) return found;
        }
    }
    {
        static const wchar_t *pf[] = { L"ProgramFiles", L"ProgramFiles(x86)" };
        for (i = 0; i < sizeof(pf) / sizeof(pf[0]); ++i) {
            wchar_t *base = env_dup(pf[i]);
            if (base) {
                found = find_in_dir(base);
                free(base);
                if (found) return found;
            }
        }
    }
    {
        wchar_t buf[PATH_CAP];
        DWORD n = GetModuleFileNameW(NULL, buf, PATH_CAP);
        if (n > 0 && n < PATH_CAP) {
            wchar_t *slash = wcsrchr(buf, L'\\');
            if (slash) {
                *slash = L'\0';
                exe = xwcsdup(buf);
                if (exe) {
                    found = find_in_dir(exe);
                    free(exe);
                    if (found) return found;
                }
            }
        }
    }
    {
        wchar_t cwd[PATH_CAP];
        DWORD n = GetCurrentDirectoryW(PATH_CAP, cwd);
        if (n > 0 && n < PATH_CAP) {
            found = find_in_dir(cwd);
            if (found) return found;
        }
    }
    return NULL;
}

static wchar_t *resolve_db_path(const wchar_t *setting, wchar_t *err, size_t errcap)
{
    if (setting && setting[0]) {
        wchar_t *full = GetFullPathDup(setting);
        if (!full) {
            StringCchCopyW(err, errcap, L"需要密钥库：路径无效");
            return NULL;
        }
        if (IsDirectoryW(full)) {
            wchar_t *found = find_in_dir(full);
            free(full);
            if (!found) {
                StringCchCopyW(err, errcap, L"需要密钥库：指定目录中未找到 KGMusicV3.db");
            }
            return found;
        }
        if (!FileExistsW(full)) {
            free(full);
            StringCchCopyW(err, errcap, L"需要密钥库：路径不存在");
            return NULL;
        }
        return full;
    }
    {
        wchar_t *found = KeyDb_AutoDetect();
        if (!found) {
            StringCchCopyW(err, errcap,
                           L"需要密钥库：未找到 KGMusicV3.db（请指定密钥库文件或酷狗安装目录）");
        }
        return found;
    }
}

KeyDbCache *KeyDbCache_Create(void)
{
    KeyDbCache *cache = (KeyDbCache *)xcalloc(1, sizeof(KeyDbCache));
    return cache;
}

void KeyDbCache_Free(KeyDbCache *cache)
{
    if (!cache) return;
    db_close(cache->db);
    free(cache->setting);
    free(cache);
}

const char *KeyDbCache_Lookup(KeyDbCache *cache, const wchar_t *setting,
                              const char *hash, wchar_t *err, size_t errcap)
{
    wchar_t *norm;
    const char *result;

    if (!cache) {
        StringCchCopyW(err, errcap, L"密钥库未初始化");
        return NULL;
    }
    norm = setting ? xwcsdup(setting) : xwcsdup(L"");
    if (!norm) {
        StringCchCopyW(err, errcap, L"内存不足");
        return NULL;
    }
    if (cache->attempted &&
        ((!cache->setting && norm[0] == L'\0') ||
         (cache->setting && wcscmp(cache->setting, norm) == 0))) {
        if (cache->failed) {
            StringCchCopyW(err, errcap, cache->error);
            free(norm);
            return NULL;
        }
    } else {
        if (cache->db) {
            db_close(cache->db);
            cache->db = NULL;
        }
        free(cache->setting);
        cache->setting = xwcsdup(norm);
        cache->attempted = true;
        cache->failed = false;
        cache->error[0] = L'\0';
        {
            wchar_t *path = resolve_db_path(norm, cache->error, ERR_CAP);
            if (!path) {
                cache->failed = true;
                StringCchCopyW(err, errcap, cache->error);
                free(norm);
                return NULL;
            }
            cache->db = db_open(path, cache->error, ERR_CAP);
            free(path);
            if (!cache->db) {
                cache->failed = true;
                StringCchCopyW(err, errcap, cache->error);
                free(norm);
                return NULL;
            }
        }
    }
    free(norm);
    result = db_lookup(cache->db, hash);
    if (!result) {
        StringCchCopyW(err, errcap, L"解密失败：密钥库中未找到该文件的密钥");
        return NULL;
    }
    return result;
}
