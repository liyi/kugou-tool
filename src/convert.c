#include "convert.h"
#include "audio.h"
#include "krc.h"
#include "util.h"

#include <strsafe.h>
#include <string.h>

#define COPY_CHUNK (1024u * 1024u)
#define KRC_MAX_FILE (64u * 1024u * 1024u)

static bool stop_requested(ConvertContext *ctx)
{
    if (!ctx || !ctx->stop) return false;
    return InterlockedCompareExchange(ctx->stop, 0, 0) != 0;
}

static wchar_t *dir_name_dup(const wchar_t *path)
{
    const wchar_t *name;
    size_t n;
    wchar_t *out;
    if (!path) return NULL;
    name = FileNamePtr(path);
    n = (size_t)(name - path);
    if (n == 0) return xwcsdup(L".");
    out = (wchar_t *)xmalloc((n + 1) * sizeof(wchar_t));
    if (!out) return NULL;
    memcpy(out, path, n * sizeof(wchar_t));
    out[n] = L'\0';
    return out;
}

static bool build_target_path(const TaskItem *item, ConvertContext *ctx,
                              const wchar_t *ext, bool unrecognized,
                              wchar_t **out, wchar_t *err, size_t errcap)
{
    wchar_t *dir = NULL;
    wchar_t *base = NULL;
    wchar_t *name = NULL;
    wchar_t *target = NULL;
    size_t need;
    const wchar_t *suffix = unrecognized ? L"_未识别格式" : L"";

    *out = NULL;
    if (ctx->opts.out_dir && ctx->opts.out_dir[0]) {
        dir = xwcsdup(ctx->opts.out_dir);
    } else {
        dir = dir_name_dup(item->path);
    }
    if (!dir) {
        StringCchCopyW(err, errcap, L"内存不足");
        return false;
    }
    base = StripExtension(item->name);
    if (!base) {
        free(dir);
        StringCchCopyW(err, errcap, L"内存不足");
        return false;
    }
    need = wcslen(base) + wcslen(suffix) + wcslen(ext) + 2;
    name = (wchar_t *)xmalloc(need * sizeof(wchar_t));
    if (!name) {
        free(dir);
        free(base);
        StringCchCopyW(err, errcap, L"内存不足");
        return false;
    }
    StringCchPrintfW(name, need, L"%s%s.%s", base, suffix, ext);
    target = JoinPath(dir, name);
    free(name);
    free(base);
    free(dir);
    if (!target) {
        StringCchCopyW(err, errcap, L"内存不足");
        return false;
    }
    if (wcslen(target) >= PATH_CAP) {
        free(target);
        StringCchCopyW(err, errcap, L"路径过长");
        return false;
    }
    *out = target;
    return true;
}

static bool target_exists(const wchar_t *target, bool *is_dir,
                          wchar_t *err, size_t errcap)
{
    wchar_t *lp = MakeLongPath(target);
    DWORD attr;
    if (!lp) {
        StringCchCopyW(err, errcap, L"内存不足");
        return false;
    }
    attr = GetFileAttributesW(lp);
    free(lp);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        *is_dir = false;
        return false;
    }
    *is_dir = (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
    return true;
}

static ConvResult apply_overwrite(ConvertContext *ctx, const wchar_t *target,
                                  bool *proceed, wchar_t *reason, size_t reason_cap)
{
    bool is_dir = false;
    bool exists;

    *proceed = true;
    if (stop_requested(ctx)) return CONV_STOPPED;
    exists = target_exists(target, &is_dir, reason, reason_cap);
    if (!exists) return CONV_SUCCESS;
    if (is_dir) {
        StringCchCopyW(reason, reason_cap, L"目标路径已存在同名目录");
        return CONV_FAILED;
    }
    if (ctx->overwrite == OW_YES_ALL) return CONV_SUCCESS;
    if (ctx->overwrite == OW_NO_ALL) {
        *proceed = false;
        StringCchCopyW(reason, reason_cap, L"目标文件已存在");
        return CONV_SKIPPED;
    }
    if (!ctx->prompt_overwrite) {
        *proceed = false;
        StringCchCopyW(reason, reason_cap, L"目标文件已存在");
        return CONV_SKIPPED;
    }
    {
        int answer = ctx->prompt_overwrite(ctx->prompt_ctx, target);
        if (answer < 0) return CONV_STOPPED;
        if (answer == 0) {
            *proceed = false;
            StringCchCopyW(reason, reason_cap, L"目标文件已存在");
            return CONV_SKIPPED;
        }
        if (answer == 2) {
            ctx->overwrite = OW_YES_ALL;
        } else if (answer == 3) {
            ctx->overwrite = OW_NO_ALL;
            *proceed = false;
            StringCchCopyW(reason, reason_cap, L"目标文件已存在");
            return CONV_SKIPPED;
        }
    }
    return CONV_SUCCESS;
}

static HANDLE create_temp_file(const wchar_t *target, wchar_t **temp_path,
                               wchar_t *err, size_t errcap)
{
    wchar_t *dir = dir_name_dup(target);
    DWORD pid = GetCurrentProcessId();
    unsigned attempt;

    *temp_path = NULL;
    if (!dir) {
        StringCchCopyW(err, errcap, L"内存不足");
        return INVALID_HANDLE_VALUE;
    }
    if (!EnsureDirectoryTree(dir, err, errcap)) {
        free(dir);
        return INVALID_HANDLE_VALUE;
    }
    for (attempt = 0; attempt < 200; ++attempt) {
        wchar_t name[96];
        wchar_t *temp;
        wchar_t *lp;
        HANDLE h;

        StringCchPrintfW(name, 96, L"~kut-%lu-%u.tmp", (unsigned long)pid, attempt);
        temp = JoinPath(dir, name);
        if (!temp) break;
        lp = MakeLongPath(temp);
        if (!lp) {
            free(temp);
            break;
        }
        h = CreateFileW(lp, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        free(lp);
        if (h != INVALID_HANDLE_VALUE) {
            *temp_path = temp;
            free(dir);
            return h;
        }
        {
            DWORD code = GetLastError();
            free(temp);
            if (code != ERROR_FILE_EXISTS && code != ERROR_ALREADY_EXISTS) {
                FormatWin32Error(L"写盘失败", code, err, errcap);
                free(dir);
                return INVALID_HANDLE_VALUE;
            }
        }
    }
    if (err[0] == L'\0') StringCchCopyW(err, errcap, L"写盘失败：无法创建临时文件");
    free(dir);
    return INVALID_HANDLE_VALUE;
}

static bool write_all(HANDLE h, const uint8_t *data, size_t len,
                      wchar_t *err, size_t errcap)
{
    size_t done = 0;
    while (done < len) {
        DWORD chunk = (DWORD)(len - done > 0x7FFFFFFF ? 0x7FFFFFFF : len - done);
        DWORD wrote = 0;
        if (!WriteFile(h, data + done, chunk, &wrote, NULL)) {
            FormatWin32Error(L"写盘失败", GetLastError(), err, errcap);
            return false;
        }
        if (wrote == 0) {
            StringCchCopyW(err, errcap, L"写盘失败：磁盘空间不足");
            return false;
        }
        done += wrote;
    }
    return true;
}

static void delete_file_long(const wchar_t *path)
{
    wchar_t *lp;
    if (!path) return;
    lp = MakeLongPath(path);
    if (lp) {
        DeleteFileW(lp);
        free(lp);
    }
}

static ConvResult finish_file(HANDLE h, const wchar_t *temp,
                              const wchar_t *target,
                              wchar_t *reason, size_t reason_cap)
{
    wchar_t *lp_temp;
    wchar_t *lp_target;

    if (!CloseHandle(h)) {
        delete_file_long(temp);
        StringCchCopyW(reason, reason_cap, L"写盘失败");
        return CONV_FAILED;
    }
    lp_temp = MakeLongPath(temp);
    lp_target = MakeLongPath(target);
    if (!lp_temp || !lp_target) {
        free(lp_temp);
        free(lp_target);
        DeleteFileW(temp);
        StringCchCopyW(reason, reason_cap, L"内存不足");
        return CONV_FAILED;
    }
    if (!MoveFileExW(lp_temp, lp_target, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        FormatWin32Error(L"写盘失败", GetLastError(), reason, reason_cap);
        DeleteFileW(lp_temp);
        free(lp_temp);
        free(lp_target);
        return CONV_FAILED;
    }
    free(lp_temp);
    free(lp_target);
    return CONV_SUCCESS;
}

static void delete_temp(HANDLE h, const wchar_t *temp)
{
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    delete_file_long(temp);
}

static ConvResult convert_krc(TaskItem *item, ConvertContext *ctx,
                              wchar_t *out_path, size_t out_path_cap,
                              wchar_t *reason, size_t reason_cap)
{
    uint8_t *data = NULL;
    size_t len = 0;
    uint8_t *lrc = NULL;
    size_t lrc_len = 0;
    wchar_t *target = NULL;
    wchar_t *temp = NULL;
    HANDLE out = INVALID_HANDLE_VALUE;
    bool proceed = true;
    ConvResult result;

    if (stop_requested(ctx)) return CONV_STOPPED;
    if (!ReadWholeFile(item->path, &data, &len, KRC_MAX_FILE, reason, reason_cap)) {
        return CONV_FAILED;
    }
    if (!KrcToLrc(data, len, ctx->opts.enc, &lrc, &lrc_len, reason, reason_cap)) {
        free(data);
        return CONV_FAILED;
    }
    free(data);
    if (stop_requested(ctx)) {
        free(lrc);
        return CONV_STOPPED;
    }
    if (!build_target_path(item, ctx, L"lrc", false, &target, reason, reason_cap)) {
        free(lrc);
        return CONV_FAILED;
    }
    result = apply_overwrite(ctx, target, &proceed, reason, reason_cap);
    if (result != CONV_SUCCESS || !proceed) {
        free(lrc);
        free(target);
        return result;
    }
    out = create_temp_file(target, &temp, reason, reason_cap);
    if (out == INVALID_HANDLE_VALUE) {
        free(lrc);
        free(target);
        return CONV_FAILED;
    }
    if (!write_all(out, lrc, lrc_len, reason, reason_cap)) {
        delete_temp(out, temp);
        free(lrc);
        free(temp);
        free(target);
        return CONV_FAILED;
    }
    free(lrc);
    result = finish_file(out, temp, target, reason, reason_cap);
    if (result == CONV_SUCCESS) {
        StringCchCopyW(out_path, out_path_cap, target);
    }
    free(temp);
    free(target);
    return result;
}

static ConvResult convert_audio(TaskItem *item, ConvertContext *ctx,
                                wchar_t *out_path, size_t out_path_cap,
                                wchar_t *reason, size_t reason_cap)
{
    AudioDecryptor *dec = NULL;
    uint64_t audio_size;
    uint8_t head[64];
    size_t head_len;
    const wchar_t *ext;
    bool recognized = false;
    wchar_t *target = NULL;
    wchar_t *temp = NULL;
    HANDLE out = INVALID_HANDLE_VALUE;
    uint8_t *buf = NULL;
    uint64_t off;
    bool proceed = true;
    ConvResult result;
    bool unrecognized;

    if (stop_requested(ctx)) return CONV_STOPPED;
    dec = AudioOpen(item->path, ctx->keydb, ctx->opts.keydb, reason, reason_cap);
    if (!dec) return CONV_FAILED;
    audio_size = AudioSize(dec);
    if (audio_size == 0) {
        AudioClose(dec);
        StringCchCopyW(reason, reason_cap, L"解密失败：音频数据为空");
        return CONV_FAILED;
    }
    head_len = (size_t)(audio_size < sizeof(head) ? audio_size : sizeof(head));
    if (!AudioReadDecrypted(dec, 0, head, head_len, reason, reason_cap)) {
        AudioClose(dec);
        return CONV_FAILED;
    }
    ext = SniffAudioExt(head, head_len, &recognized);
    unrecognized = !recognized;
    if (stop_requested(ctx)) {
        AudioClose(dec);
        return CONV_STOPPED;
    }
    if (!build_target_path(item, ctx, ext, unrecognized, &target, reason, reason_cap)) {
        AudioClose(dec);
        return CONV_FAILED;
    }
    result = apply_overwrite(ctx, target, &proceed, reason, reason_cap);
    if (result != CONV_SUCCESS || !proceed) {
        AudioClose(dec);
        free(target);
        return result;
    }
    out = create_temp_file(target, &temp, reason, reason_cap);
    if (out == INVALID_HANDLE_VALUE) {
        AudioClose(dec);
        free(target);
        return CONV_FAILED;
    }
    buf = (uint8_t *)xmalloc(COPY_CHUNK);
    if (!buf) {
        delete_temp(out, temp);
        AudioClose(dec);
        free(temp);
        free(target);
        StringCchCopyW(reason, reason_cap, L"内存不足");
        return CONV_FAILED;
    }
    result = CONV_SUCCESS;
    for (off = 0; off < audio_size; off += COPY_CHUNK) {
        size_t n = (size_t)((audio_size - off) > COPY_CHUNK ? COPY_CHUNK : (audio_size - off));
        if (stop_requested(ctx)) {
            result = CONV_STOPPED;
            break;
        }
        if (!AudioReadDecrypted(dec, off, buf, n, reason, reason_cap)) {
            result = CONV_FAILED;
            break;
        }
        if (!write_all(out, buf, n, reason, reason_cap)) {
            result = CONV_FAILED;
            break;
        }
    }
    free(buf);
    AudioClose(dec);
    if (result != CONV_SUCCESS) {
        delete_temp(out, temp);
        free(temp);
        free(target);
        return result;
    }
    result = finish_file(out, temp, target, reason, reason_cap);
    if (result == CONV_SUCCESS) {
        StringCchCopyW(out_path, out_path_cap, target);
        result = unrecognized ? CONV_UNRECOGNIZED : CONV_SUCCESS;
    }
    free(temp);
    free(target);
    return result;
}

ConvResult ConvertItem(TaskItem *item, ConvertContext *ctx,
                       wchar_t *out_path, size_t out_path_cap,
                       wchar_t *reason, size_t reason_cap)
{
    out_path[0] = L'\0';
    reason[0] = L'\0';
    if (!item || !ctx) {
        StringCchCopyW(reason, reason_cap, L"内部错误");
        return CONV_FAILED;
    }
    switch (item->kind) {
    case KIND_KRC:
        return convert_krc(item, ctx, out_path, out_path_cap, reason, reason_cap);
    case KIND_KGG:
    case KIND_KGMA:
    case KIND_KGM:
    case KIND_VPR:
        return convert_audio(item, ctx, out_path, out_path_cap, reason, reason_cap);
    default:
        StringCchCopyW(reason, reason_cap, L"不支持的文件类型");
        return CONV_FAILED;
    }
}
