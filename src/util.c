#include "util.h"

#include <strsafe.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

void *xmalloc(size_t size)
{
    if (size == 0) size = 1;
    return malloc(size);
}

void *xcalloc(size_t count, size_t size)
{
    if (count == 0 || size == 0) return calloc(1, 1);
    return calloc(count, size);
}

void *xrealloc(void *ptr, size_t size)
{
    if (size == 0) size = 1;
    return realloc(ptr, size);
}

wchar_t *xwcsdup(const wchar_t *s)
{
    size_t n;
    wchar_t *p;
    if (!s) return NULL;
    n = wcslen(s) + 1;
    p = (wchar_t *)xmalloc(n * sizeof(wchar_t));
    if (p) memcpy(p, s, n * sizeof(wchar_t));
    return p;
}

char *xstrdup(const char *s)
{
    size_t n;
    char *p;
    if (!s) return NULL;
    n = strlen(s) + 1;
    p = (char *)xmalloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

void BB_Init(ByteBuf *b)
{
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

void BB_Free(ByteBuf *b)
{
    free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

bool BB_Reserve(ByteBuf *b, size_t extra)
{
    size_t need;
    size_t cap;
    uint8_t *p;

    if (extra > SIZE_MAX - b->len) return false;
    need = b->len + extra;
    if (need <= b->cap) return true;
    cap = b->cap ? b->cap : 256;
    while (cap < need) {
        if (cap > SIZE_MAX / 2) {
            cap = need;
            break;
        }
        cap *= 2;
    }
    p = (uint8_t *)xrealloc(b->data, cap);
    if (!p) return false;
    b->data = p;
    b->cap = cap;
    return true;
}

bool BB_Append(ByteBuf *b, const void *data, size_t len)
{
    if (len == 0) return true;
    if (!BB_Reserve(b, len)) return false;
    memcpy(b->data + b->len, data, len);
    b->len += len;
    return true;
}

bool BB_AppendByte(ByteBuf *b, uint8_t c)
{
    if (!BB_Reserve(b, 1)) return false;
    b->data[b->len++] = c;
    return true;
}

bool BB_AppendStr(ByteBuf *b, const char *s)
{
    return BB_Append(b, s, strlen(s));
}

bool BB_AppendWideN(ByteBuf *b, const wchar_t *s, size_t chars)
{
    int bytes;
    size_t old_len;
    if (chars == 0) return true;
    if (chars > (size_t)INT_MAX) return false;
    bytes = WideCharToMultiByte(CP_UTF8, 0, s, (int)chars, NULL, 0, NULL, NULL);
    if (bytes <= 0) return false;
    old_len = b->len;
    if (!BB_Reserve(b, (size_t)bytes)) return false;
    if (WideCharToMultiByte(CP_UTF8, 0, s, (int)chars,
                            (char *)b->data + old_len, bytes, NULL, NULL) <= 0) {
        return false;
    }
    b->len += (size_t)bytes;
    return true;
}

bool BB_AppendWide(ByteBuf *b, const wchar_t *s)
{
    return BB_AppendWideN(b, s, wcslen(s));
}

bool BB_AppendFmt(ByteBuf *b, const char *fmt, ...)
{
    va_list ap;
    size_t cap = 256;
    bool ok = false;

    for (;;) {
        char *tmp;
        int n;
        va_list copy;
        if (cap > 1024 * 1024) return false;
        tmp = (char *)xmalloc(cap);
        if (!tmp) return false;
        va_start(ap, fmt);
        va_copy(copy, ap);
        n = vsnprintf(tmp, cap, fmt, copy);
        va_end(copy);
        va_end(ap);
        if (n >= 0) {
            if ((size_t)n < cap) {
                ok = BB_Append(b, tmp, (size_t)n);
                free(tmp);
                return ok;
            }
            cap = (size_t)n + 1;
        } else {
            cap *= 2;
        }
        free(tmp);
    }
}

wchar_t *Utf8ToWideN(const char *s, size_t len)
{
    int chars;
    wchar_t *out;
    if (!s) return NULL;
    if (len > (size_t)INT_MAX) return NULL;
    chars = MultiByteToWideChar(CP_UTF8, 0, s, (int)len, NULL, 0);
    if (chars <= 0 && len != 0) return NULL;
    out = (wchar_t *)xmalloc(((size_t)chars + 1) * sizeof(wchar_t));
    if (!out) return NULL;
    if (chars > 0) {
        MultiByteToWideChar(CP_UTF8, 0, s, (int)len, out, chars);
    }
    out[chars] = L'\0';
    return out;
}

char *WideToUtf8(const wchar_t *s)
{
    return WideToCodepage(s, CP_UTF8);
}

char *WideToCodepage(const wchar_t *s, UINT codepage)
{
    int bytes;
    char *out;
    if (!s) return NULL;
    bytes = WideCharToMultiByte(codepage, 0, s, -1, NULL, 0, NULL, NULL);
    if (bytes <= 0) return NULL;
    out = (char *)xmalloc((size_t)bytes);
    if (!out) return NULL;
    if (WideCharToMultiByte(codepage, 0, s, -1, out, bytes, NULL, NULL) <= 0) {
        free(out);
        return NULL;
    }
    return out;
}

static bool path_is_absolute(const wchar_t *p)
{
    if (p[0] != 0 && p[1] == L':' && (p[2] == (wchar_t)92 || p[2] == L'/')) return true;
    if (p[0] == (wchar_t)92 && p[1] == (wchar_t)92) return true;
    return false;
}

wchar_t *GetFullPathDup(const wchar_t *path)
{
    DWORD cap = 512;
    wchar_t *buf = NULL;

    if (!path || !path[0]) return NULL;
    for (;;) {
        DWORD n;
        wchar_t *p = (wchar_t *)xrealloc(buf, (size_t)cap * sizeof(wchar_t));
        if (!p) {
            free(buf);
            return NULL;
        }
        buf = p;
        n = GetFullPathNameW(path, cap, buf, NULL);
        if (n == 0) {
            size_t i;
            free(buf);
            if (path_is_absolute(path)) {
                wchar_t *dup = xwcsdup(path);
                if (dup) {
                    for (i = 0; dup[i]; ++i) {
                        if (dup[i] == L'/') dup[i] = (wchar_t)92;
                    }
                }
                return dup;
            }
            {
                wchar_t cwd[PATH_CAP];
                DWORD c = GetCurrentDirectoryW(PATH_CAP, cwd);
                if (c > 0 && c < PATH_CAP) return JoinPath(cwd, path);
            }
            return NULL;
        }
        if (n < cap) return buf;
        cap = n + 1;
    }
}

wchar_t *MakeLongPath(const wchar_t *path)
{
    wchar_t *full;
    wchar_t *out;
    size_t len;

    if (!path || !path[0]) return NULL;
    if (wcsncmp(path, L"\\\\?\\", 4) == 0 || wcsncmp(path, L"\\\\.\\", 4) == 0) {
        return xwcsdup(path);
    }
    full = GetFullPathDup(path);
    if (!full) return NULL;
    len = wcslen(full);
    if (len >= 2 && full[0] == L'\\' && full[1] == L'\\') {
        out = (wchar_t *)xmalloc((len + 8) * sizeof(wchar_t));
        if (out) {
            StringCchPrintfW(out, len + 8, L"\\\\?\\UNC\\%s", full + 2);
        }
    } else {
        out = (wchar_t *)xmalloc((len + 5) * sizeof(wchar_t));
        if (out) {
            StringCchPrintfW(out, len + 5, L"\\\\?\\%s", full);
        }
    }
    free(full);
    return out;
}

wchar_t *JoinPath(const wchar_t *dir, const wchar_t *name)
{
    size_t dlen;
    size_t nlen;
    bool slash;
    wchar_t *out;

    if (!dir) return xwcsdup(name);
    if (!name) return xwcsdup(dir);
    dlen = wcslen(dir);
    nlen = wcslen(name);
    slash = (dlen > 0 && dir[dlen - 1] != L'\\' && dir[dlen - 1] != L'/');
    out = (wchar_t *)xmalloc((dlen + nlen + (slash ? 2 : 1)) * sizeof(wchar_t));
    if (!out) return NULL;
    memcpy(out, dir, dlen * sizeof(wchar_t));
    if (slash) out[dlen++] = L'\\';
    memcpy(out + dlen, name, (nlen + 1) * sizeof(wchar_t));
    return out;
}

const wchar_t *FileNamePtr(const wchar_t *path)
{
    const wchar_t *p;
    const wchar_t *last = path;
    if (!path) return L"";
    for (p = path; *p; ++p) {
        if (*p == L'\\' || *p == L'/') last = p + 1;
    }
    return last;
}

const wchar_t *ExtPtr(const wchar_t *path)
{
    const wchar_t *name;
    const wchar_t *dot = NULL;
    const wchar_t *p;
    if (!path) return NULL;
    name = FileNamePtr(path);
    for (p = name; *p; ++p) {
        if (*p == L'.') dot = p;
    }
    return dot;
}

bool ExtEquals(const wchar_t *path, const wchar_t *ext)
{
    const wchar_t *e = ExtPtr(path);
    if (!e || !ext) return false;
    return _wcsicmp(e, ext) == 0;
}

wchar_t *StripExtension(const wchar_t *path)
{
    const wchar_t *e;
    size_t n;
    wchar_t *out;
    if (!path) return NULL;
    e = ExtPtr(path);
    n = e ? (size_t)(e - path) : wcslen(path);
    out = (wchar_t *)xmalloc((n + 1) * sizeof(wchar_t));
    if (!out) return NULL;
    memcpy(out, path, n * sizeof(wchar_t));
    out[n] = L'\0';
    return out;
}

wchar_t *ReplaceExtension(const wchar_t *path, const wchar_t *ext)
{
    wchar_t *base = StripExtension(path);
    wchar_t *out;
    size_t blen;
    size_t elen;
    if (!base) return NULL;
    blen = wcslen(base);
    elen = wcslen(ext);
    out = (wchar_t *)xrealloc(base, (blen + elen + 1) * sizeof(wchar_t));
    if (!out) {
        free(base);
        return NULL;
    }
    memcpy(out + blen, ext, (elen + 1) * sizeof(wchar_t));
    return out;
}

bool FileExistsW(const wchar_t *path)
{
    wchar_t *lp;
    DWORD attr;
    if (!path) return false;
    lp = MakeLongPath(path);
    if (!lp) return false;
    attr = GetFileAttributesW(lp);
    free(lp);
    return attr != INVALID_FILE_ATTRIBUTES;
}

bool IsDirectoryW(const wchar_t *path)
{
    wchar_t *lp;
    DWORD attr;
    if (!path) return false;
    lp = MakeLongPath(path);
    if (!lp) return false;
    attr = GetFileAttributesW(lp);
    free(lp);
    return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

uint64_t FileSizeW(const wchar_t *path, bool *ok)
{
    wchar_t *lp;
    WIN32_FILE_ATTRIBUTE_DATA fad;
    uint64_t size = 0;
    bool good = false;

    if (ok) *ok = false;
    if (!path) return 0;
    lp = MakeLongPath(path);
    if (!lp) return 0;
    if (GetFileAttributesExW(lp, GetFileExInfoStandard, &fad)) {
        size = ((uint64_t)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
        good = true;
    }
    free(lp);
    if (ok) *ok = good;
    return size;
}

void FormatSize(uint64_t size, wchar_t *buf, size_t cap)
{
    double v;
    if (size < 1024) {
        StringCchPrintfW(buf, cap, L"%llu B", (unsigned long long)size);
    } else if (size < 1024ULL * 1024ULL) {
        v = (double)size / 1024.0;
        StringCchPrintfW(buf, cap, L"%.1f KB", v);
    } else if (size < 1024ULL * 1024ULL * 1024ULL) {
        v = (double)size / (1024.0 * 1024.0);
        StringCchPrintfW(buf, cap, L"%.1f MB", v);
    } else {
        v = (double)size / (1024.0 * 1024.0 * 1024.0);
        StringCchPrintfW(buf, cap, L"%.2f GB", v);
    }
}

void FormatWin32Error(const wchar_t *prefix, DWORD code, wchar_t *err, size_t errcap)
{
    wchar_t *sysmsg = NULL;
    DWORD n;
    wchar_t *msg = NULL;

    n = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                           FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL, code, 0, (LPWSTR)&msg, 0, NULL);
    if (n && msg) {
        size_t len = wcslen(msg);
        while (len > 0 && (msg[len - 1] == L'\r' || msg[len - 1] == L'\n' ||
                           msg[len - 1] == L' ' || msg[len - 1] == L'.')) {
            msg[--len] = L'\0';
        }
        sysmsg = xwcsdup(msg);
    }
    LocalFree(msg);
    if (prefix && prefix[0]) {
        if (sysmsg && sysmsg[0]) {
            StringCchPrintfW(err, errcap, L"%s：%s", prefix, sysmsg);
        } else {
            StringCchPrintfW(err, errcap, L"%s（错误 %lu）", prefix, (unsigned long)code);
        }
    } else {
        if (sysmsg && sysmsg[0]) {
            StringCchCopyW(err, errcap, sysmsg);
        } else {
            StringCchPrintfW(err, errcap, L"错误 %lu", (unsigned long)code);
        }
    }
    free(sysmsg);
}

static bool EnsureDirLong(const wchar_t *long_path, wchar_t *err, size_t errcap)
{
    if (CreateDirectoryW(long_path, NULL)) return true;
    {
        DWORD code = GetLastError();
        if (code == ERROR_ALREADY_EXISTS) {
            DWORD attr = GetFileAttributesW(long_path);
            if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
                return true;
            }
            StringCchPrintfW(err, errcap, L"路径已存在但不是目录：%s", long_path);
            return false;
        }
        if (code == ERROR_PATH_NOT_FOUND) {
            wchar_t *parent = xwcsdup(long_path);
            wchar_t *slash;
            bool ok;
            if (!parent) {
                StringCchCopyW(err, errcap, L"内存不足");
                return false;
            }
            slash = wcsrchr(parent, L'\\');
            if (!slash) {
                free(parent);
                StringCchPrintfW(err, errcap, L"无法创建目录：%s", long_path);
                return false;
            }
            *slash = L'\0';
            if (parent[0] == L'\0' ||
                (wcslen(parent) >= 2 && parent[wcslen(parent) - 1] == L':')) {
                free(parent);
                StringCchPrintfW(err, errcap, L"无法创建目录：%s", long_path);
                return false;
            }
            ok = EnsureDirLong(parent, err, errcap);
            free(parent);
            if (!ok) return false;
            if (CreateDirectoryW(long_path, NULL)) return true;
            code = GetLastError();
            if (code == ERROR_ALREADY_EXISTS) {
                DWORD attr = GetFileAttributesW(long_path);
                if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
                    return true;
                }
            }
        }
        FormatWin32Error(L"无法创建输出目录", code, err, errcap);
        return false;
    }
}

bool EnsureDirectoryTree(const wchar_t *path, wchar_t *err, size_t errcap)
{
    wchar_t *full;
    wchar_t *lp;
    bool ok;
    if (!path || !path[0]) {
        StringCchCopyW(err, errcap, L"目录路径为空");
        return false;
    }
    full = GetFullPathDup(path);
    if (!full) {
        StringCchCopyW(err, errcap, L"无效的目录路径");
        return false;
    }
    lp = MakeLongPath(full);
    free(full);
    if (!lp) {
        StringCchCopyW(err, errcap, L"内存不足");
        return false;
    }
    ok = EnsureDirLong(lp, err, errcap);
    free(lp);
    return ok;
}

wchar_t *TrimW(wchar_t *s)
{
    wchar_t *end;
    if (!s) return s;
    while (*s == L' ' || *s == L'\t' || *s == L'\r' || *s == L'\n') ++s;
    end = s + wcslen(s);
    while (end > s && (end[-1] == L' ' || end[-1] == L'\t' ||
                       end[-1] == L'\r' || end[-1] == L'\n')) {
        --end;
    }
    *end = L'\0';
    return s;
}

wchar_t *NormalizePathKey(const wchar_t *path)
{
    wchar_t *full;
    wchar_t *out;
    size_t len;
    size_t i;

    if (!path) return NULL;
    full = GetFullPathDup(path);
    if (!full) full = xwcsdup(path);
    if (!full) return NULL;

    if (wcsncmp(full, L"\\\\?\\UNC\\", 8) == 0) {
        len = wcslen(full) - 8;
        out = (wchar_t *)xmalloc((len + 3) * sizeof(wchar_t));
        if (!out) {
            free(full);
            return NULL;
        }
        out[0] = L'\\';
        out[1] = L'\\';
        memcpy(out + 2, full + 8, (len + 1) * sizeof(wchar_t));
        free(full);
    } else if (wcsncmp(full, L"\\\\?\\", 4) == 0) {
        out = xwcsdup(full + 4);
        free(full);
    } else {
        out = full;
    }
    if (!out) return NULL;

    for (i = 0; out[i]; ++i) {
        if (out[i] == L'/') out[i] = L'\\';
    }
    CharLowerBuffW(out, (DWORD)wcslen(out));
    return out;
}

typedef struct PathNode {
    struct PathNode *next;
    uint64_t hash;
    wchar_t *key;
} PathNode;

struct PathSet {
    PathNode **buckets;
    size_t bucket_count;
    size_t count;
};

static uint64_t HashWide(const wchar_t *s)
{
    uint64_t h = 1469598103934665603ULL;
    while (*s) {
        h ^= (uint64_t)(*s & 0xFFFFu);
        h *= 1099511628211ULL;
        ++s;
    }
    return h;
}

PathSet *PathSet_Create(void)
{
    PathSet *set = (PathSet *)xcalloc(1, sizeof(PathSet));
    if (!set) return NULL;
    set->bucket_count = 1024;
    set->buckets = (PathNode **)xcalloc(set->bucket_count, sizeof(PathNode *));
    if (!set->buckets) {
        free(set);
        return NULL;
    }
    return set;
}

static void PathSet_FreeNodes(PathSet *set)
{
    size_t i;
    if (!set || !set->buckets) return;
    for (i = 0; i < set->bucket_count; ++i) {
        PathNode *n = set->buckets[i];
        while (n) {
            PathNode *next = n->next;
            free(n->key);
            free(n);
            n = next;
        }
        set->buckets[i] = NULL;
    }
    set->count = 0;
}

void PathSet_Clear(PathSet *set)
{
    if (!set) return;
    PathSet_FreeNodes(set);
}

void PathSet_Destroy(PathSet *set)
{
    if (!set) return;
    PathSet_FreeNodes(set);
    free(set->buckets);
    free(set);
}

static bool PathSet_Grow(PathSet *set)
{
    size_t new_count = set->bucket_count * 2;
    PathNode **new_buckets;
    size_t i;
    if (new_count < set->bucket_count) return false;
    new_buckets = (PathNode **)xcalloc(new_count, sizeof(PathNode *));
    if (!new_buckets) return false;
    for (i = 0; i < set->bucket_count; ++i) {
        PathNode *n = set->buckets[i];
        while (n) {
            PathNode *next = n->next;
            size_t idx = (size_t)(n->hash & (uint64_t)(new_count - 1));
            n->next = new_buckets[idx];
            new_buckets[idx] = n;
            n = next;
        }
    }
    free(set->buckets);
    set->buckets = new_buckets;
    set->bucket_count = new_count;
    return true;
}

bool PathSet_Add(PathSet *set, const wchar_t *normalized)
{
    uint64_t h;
    size_t idx;
    PathNode *n;
    if (!set || !normalized) return false;
    h = HashWide(normalized);
    idx = (size_t)(h & (uint64_t)(set->bucket_count - 1));
    for (n = set->buckets[idx]; n; n = n->next) {
        if (n->hash == h && wcscmp(n->key, normalized) == 0) return false;
    }
    if (set->count + 1 > set->bucket_count * 2) {
        if (!PathSet_Grow(set)) return false;
        idx = (size_t)(h & (uint64_t)(set->bucket_count - 1));
    }
    n = (PathNode *)xmalloc(sizeof(PathNode));
    if (!n) return false;
    n->key = xwcsdup(normalized);
    if (!n->key) {
        free(n);
        return false;
    }
    n->hash = h;
    n->next = set->buckets[idx];
    set->buckets[idx] = n;
    ++set->count;
    return true;
}

bool ReadWholeFile(const wchar_t *path, uint8_t **data, size_t *len,
                   uint64_t max_size, wchar_t *err, size_t errcap)
{
    wchar_t *lp;
    HANDLE h;
    LARGE_INTEGER size;
    uint8_t *buf;
    size_t total = 0;

    *data = NULL;
    *len = 0;
    lp = MakeLongPath(path);
    if (!lp) {
        StringCchCopyW(err, errcap, L"内存不足");
        return false;
    }
    h = CreateFileW(lp, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        FormatWin32Error(L"无法打开文件", GetLastError(), err, errcap);
        free(lp);
        return false;
    }
    free(lp);
    if (!GetFileSizeEx(h, &size)) {
        FormatWin32Error(L"无法读取文件大小", GetLastError(), err, errcap);
        CloseHandle(h);
        return false;
    }
    if (size.QuadPart < 0 || (uint64_t)size.QuadPart > max_size) {
        StringCchPrintfW(err, errcap, L"文件过大（%llu 字节）",
                         (unsigned long long)size.QuadPart);
        CloseHandle(h);
        return false;
    }
    buf = (uint8_t *)xmalloc((size_t)size.QuadPart + 1);
    if (!buf) {
        StringCchCopyW(err, errcap, L"内存不足");
        CloseHandle(h);
        return false;
    }
    while (total < (size_t)size.QuadPart) {
        DWORD want = (DWORD)(((uint64_t)size.QuadPart - total) > 0x7FFFFFFFULL
                                 ? 0x7FFFFFFF
                                 : ((uint64_t)size.QuadPart - total));
        DWORD got = 0;
        if (!ReadFile(h, buf + total, want, &got, NULL)) {
            FormatWin32Error(L"读取文件失败", GetLastError(), err, errcap);
            free(buf);
            CloseHandle(h);
            return false;
        }
        if (got == 0) break;
        total += got;
    }
    CloseHandle(h);
    buf[total] = 0;
    *data = buf;
    *len = total;
    return true;
}
