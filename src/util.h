#ifndef KUGOU_TOOL_UTIL_H
#define KUGOU_TOOL_UTIL_H

#include "app.h"

void *xmalloc(size_t size);
void *xcalloc(size_t count, size_t size);
void *xrealloc(void *ptr, size_t size);
wchar_t *xwcsdup(const wchar_t *s);
char *xstrdup(const char *s);

typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
} ByteBuf;

void BB_Init(ByteBuf *b);
void BB_Free(ByteBuf *b);
bool BB_Reserve(ByteBuf *b, size_t extra);
bool BB_Append(ByteBuf *b, const void *data, size_t len);
bool BB_AppendByte(ByteBuf *b, uint8_t c);
bool BB_AppendStr(ByteBuf *b, const char *s);
bool BB_AppendWide(ByteBuf *b, const wchar_t *s);
bool BB_AppendWideN(ByteBuf *b, const wchar_t *s, size_t chars);
bool BB_AppendFmt(ByteBuf *b, const char *fmt, ...);

wchar_t *Utf8ToWideN(const char *s, size_t len);
char *WideToUtf8(const wchar_t *s);
char *WideToCodepage(const wchar_t *s, UINT codepage);

wchar_t *GetFullPathDup(const wchar_t *path);
wchar_t *MakeLongPath(const wchar_t *path);
wchar_t *JoinPath(const wchar_t *dir, const wchar_t *name);
const wchar_t *FileNamePtr(const wchar_t *path);
const wchar_t *ExtPtr(const wchar_t *path);
bool ExtEquals(const wchar_t *path, const wchar_t *ext);
wchar_t *StripExtension(const wchar_t *path);
wchar_t *ReplaceExtension(const wchar_t *path, const wchar_t *ext);

bool FileExistsW(const wchar_t *path);
bool IsDirectoryW(const wchar_t *path);
uint64_t FileSizeW(const wchar_t *path, bool *ok);
void FormatSize(uint64_t size, wchar_t *buf, size_t cap);
bool EnsureDirectoryTree(const wchar_t *path, wchar_t *err, size_t errcap);

wchar_t *NormalizePathKey(const wchar_t *path);
wchar_t *TrimW(wchar_t *s);

typedef struct PathSet PathSet;
PathSet *PathSet_Create(void);
void PathSet_Destroy(PathSet *set);
void PathSet_Clear(PathSet *set);
bool PathSet_Add(PathSet *set, const wchar_t *normalized);

bool ReadWholeFile(const wchar_t *path, uint8_t **data, size_t *len,
                   uint64_t max_size, wchar_t *err, size_t errcap);
void FormatWin32Error(const wchar_t *prefix, DWORD code, wchar_t *err, size_t errcap);

#endif
