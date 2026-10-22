#ifndef KUGOU_TOOL_APP_H
#define KUGOU_TOOL_APP_H

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef WINVER
#define WINVER 0x0601
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef _WIN32_IE
#define _WIN32_IE 0x0700
#endif

#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <wchar.h>

#define APP_TITLE L"\u9177\u72d7\u6587\u4ef6\u8f6c\u6362\u5de5\u5177"
#define APP_VERSION L"1.0.0"

#define KRC_KEY_SIZE 16
#define ERR_CAP 512
#define STATUS_CAP 512
#define PATH_CAP 32768

typedef enum {
    KIND_UNKNOWN = 0,
    KIND_KRC,
    KIND_KGG,
    KIND_KGMA,
    KIND_KGM,
    KIND_VPR
} FileKind;

typedef enum {
    ENC_UTF8_BOM = 0,
    ENC_UTF8 = 1,
    ENC_GBK = 2
} LrcEncoding;

typedef enum {
    ST_WAITING = 0,
    ST_RUNNING,
    ST_SUCCESS,
    ST_UNRECOGNIZED,
    ST_SKIPPED,
    ST_FAILED
} ItemStatus;

typedef struct {
    wchar_t *path;
    wchar_t *name;
    uint64_t size;
    FileKind kind;
    ItemStatus status;
    wchar_t status_text[STATUS_CAP];
} TaskItem;

typedef struct {
    LrcEncoding enc;
    const wchar_t *out_dir;
    const wchar_t *keydb;
} ConvertOptions;

FileKind KindFromPath(const wchar_t *path);
const wchar_t *KindDisplayName(FileKind kind);
bool KindHasSupportedExt(const wchar_t *path);
bool IsSupportedAudioKind(FileKind kind);

#endif
