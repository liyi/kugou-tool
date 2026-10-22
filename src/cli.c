#include "cli.h"
#include "convert.h"
#include "keydb.h"
#include "util.h"

#include <strsafe.h>
#include <stdarg.h>
#include <string.h>

typedef struct {
    const wchar_t *out_dir;
    const wchar_t *keydb;
    LrcEncoding enc;
    bool recursive;
    bool verbose;
    bool force_yes;
    bool force_no;
    wchar_t **paths;
    int path_count;
} CliOptions;

typedef struct {
    TaskItem *items;
    size_t count;
    size_t cap;
} ItemList;

typedef struct {
    bool interactive;
    HANDLE input;
} PromptCtx;

static HANDLE g_out = INVALID_HANDLE_VALUE;
static HANDLE g_err = INVALID_HANDLE_VALUE;
static volatile LONG g_stop;
static bool g_path_error;
static bool g_help;

static BOOL WINAPI CtrlHandler(DWORD type)
{
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT) {
        InterlockedExchange(&g_stop, 1);
        return TRUE;
    }
    return FALSE;
}

static void console_open_stream(DWORD which, HANDLE *out, const wchar_t *device)
{
    HANDLE h = GetStdHandle(which);
    if (h == NULL || h == INVALID_HANDLE_VALUE) {
        h = CreateFileW(device, GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                        OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            SetStdHandle(which, h);
        }
    }
    *out = h;
}

void CliAttachConsole(void)
{
    HANDLE std_in = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE std_out = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE std_err = GetStdHandle(STD_ERROR_HANDLE);
    bool have_std = (std_in && std_in != INVALID_HANDLE_VALUE) ||
                    (std_out && std_out != INVALID_HANDLE_VALUE) ||
                    (std_err && std_err != INVALID_HANDLE_VALUE);
    if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
        DWORD err = GetLastError();
        if (err != ERROR_ACCESS_DENIED && !have_std) {
            AllocConsole();
        }
    }
    console_open_stream(STD_OUTPUT_HANDLE, &g_out, L"CONOUT$");
    console_open_stream(STD_ERROR_HANDLE, &g_err, L"CONOUT$");
    {
        HANDLE input = INVALID_HANDLE_VALUE;
        console_open_stream(STD_INPUT_HANDLE, &input, L"CONIN$");
    }
    if (g_err == INVALID_HANDLE_VALUE || g_err == NULL) g_err = g_out;
}

static void write_console(HANDLE h, const wchar_t *text)
{
    DWORD mode;
    size_t len;
    if (h == INVALID_HANDLE_VALUE || h == NULL || !text) return;
    len = wcslen(text);
    if (len == 0) return;
    if (GetConsoleMode(h, &mode)) {
        DWORD wrote = 0;
        size_t off = 0;
        while (off < len) {
            DWORD chunk = (DWORD)((len - off) > 0x7FFFFFFF ? 0x7FFFFFFF : (len - off));
            if (!WriteConsoleW(h, text + off, chunk, &wrote, NULL) || wrote == 0) break;
            off += wrote;
        }
        return;
    }
    {
        UINT cp = GetConsoleOutputCP();
        int bytes;
        char *buf;
        size_t off = 0;
        if (cp == 0) cp = GetACP();
        bytes = WideCharToMultiByte(cp, 0, text, (int)len, NULL, 0, NULL, NULL);
        if (bytes <= 0) return;
        buf = (char *)xmalloc((size_t)bytes);
        if (!buf) return;
        WideCharToMultiByte(cp, 0, text, (int)len, buf, bytes, NULL, NULL);
        while (off < (size_t)bytes) {
            DWORD wrote = 0;
            DWORD chunk = (DWORD)(((size_t)bytes - off) > 0x7FFFFFFF
                                      ? 0x7FFFFFFF
                                      : ((size_t)bytes - off));
            if (!WriteFile(h, buf + off, chunk, &wrote, NULL) || wrote == 0) break;
            off += wrote;
        }
        free(buf);
    }
}

static void out(const wchar_t *fmt, ...)
{
    wchar_t *buf;
    va_list ap;
    size_t cap = 32768;
    buf = (wchar_t *)xmalloc(cap * sizeof(wchar_t));
    if (!buf) return;
    va_start(ap, fmt);
    StringCchVPrintfW(buf, cap, fmt, ap);
    va_end(ap);
    write_console(g_out, buf);
    free(buf);
}

static void err(const wchar_t *fmt, ...)
{
    wchar_t *buf;
    va_list ap;
    size_t cap = 32768;
    buf = (wchar_t *)xmalloc(cap * sizeof(wchar_t));
    if (!buf) return;
    va_start(ap, fmt);
    StringCchVPrintfW(buf, cap, fmt, ap);
    va_end(ap);
    write_console(g_err, buf);
    free(buf);
}

static void print_usage_short(void)
{
    err(L"使用 -h 或 --help 查看帮助。\n");
}

static void print_help(void)
{
    out(L"酷狗文件转换工具 %s\n", APP_VERSION);
    out(L"用法：kugou-tool.exe [选项] <文件|目录> ...\n\n");
    out(L"选项：\n");
    out(L"  -o <目录>         指定输出目录（默认：源文件所在目录）\n");
    out(L"  -r                递归处理目录内的子目录\n");
    out(L"  -y                覆盖已存在的文件，不询问\n");
    out(L"  -n                跳过已存在的文件，不询问\n");
    out(L"  -e <编码>         LRC 输出编码：utf8 / utf8bom / gbk（默认 utf8bom）\n");
    out(L"  -v                显示详细信息\n");
    out(L"  --keydb <路径>    指定酷狗密钥库 KGMusicV3.db，或包含它的酷狗安装目录\n");
    out(L"  --kugou-dir <目录> 同 --keydb，可指定酷狗安装目录\n");
    out(L"  --gui             启动图形界面（忽略其余参数）\n");
    out(L"  -h, --help        显示本帮助\n\n");
    out(L"说明：\n");
    out(L"  - 不带任何参数启动图形界面。\n");
    out(L"  - 目录默认不递归，使用 -r 开启递归。\n");
    out(L"  - CLI 覆盖询问：y=是，n=否，a=全部是，s=全部否。\n");
    out(L"  - 新版 .kgg 文件需要酷狗本地密钥库；未指定时会自动探测常见路径。\n");
}

static bool parse_encoding(const wchar_t *s, LrcEncoding *enc)
{
    if (_wcsicmp(s, L"utf8") == 0 || _wcsicmp(s, L"utf-8") == 0) {
        *enc = ENC_UTF8;
        return true;
    }
    if (_wcsicmp(s, L"utf8bom") == 0 || _wcsicmp(s, L"utf-8bom") == 0 ||
        _wcsicmp(s, L"utf-8-bom") == 0) {
        *enc = ENC_UTF8_BOM;
        return true;
    }
    if (_wcsicmp(s, L"gbk") == 0) {
        *enc = ENC_GBK;
        return true;
    }
    return false;
}

static bool parse_args(int argc, wchar_t **argv, CliOptions *opt)
{
    int i;
    bool end_options = false;

    memset(opt, 0, sizeof(*opt));
    opt->enc = ENC_UTF8_BOM;
    opt->paths = (wchar_t **)xcalloc((size_t)argc, sizeof(wchar_t *));
    if (!opt->paths) return false;

    for (i = 1; i < argc; ++i) {
        const wchar_t *a = argv[i];
        if (end_options || a[0] != L'-' || a[1] == L'\0') {
            opt->paths[opt->path_count++] = argv[i];
            continue;
        }
        if (wcscmp(a, L"--") == 0) {
            end_options = true;
        } else if (wcscmp(a, L"-h") == 0 || wcscmp(a, L"--help") == 0) {
            print_help();
            g_help = true;
            return false;
        } else if (wcscmp(a, L"-r") == 0) {
            opt->recursive = true;
        } else if (wcscmp(a, L"-y") == 0) {
            opt->force_yes = true;
        } else if (wcscmp(a, L"-n") == 0) {
            opt->force_no = true;
        } else if (wcscmp(a, L"-v") == 0) {
            opt->verbose = true;
        } else if (wcscmp(a, L"-o") == 0) {
            if (i + 1 >= argc) {
                err(L"错误：-o 需要一个目录参数。\n");
                print_usage_short();
                return false;
            }
            opt->out_dir = argv[++i];
            if (opt->out_dir[0] == L'\0') {
                err(L"错误：输出目录不能为空。\n");
                return false;
            }
        } else if (wcscmp(a, L"-e") == 0) {
            if (i + 1 >= argc) {
                err(L"错误：-e 需要一个编码参数。\n");
                print_usage_short();
                return false;
            }
            if (!parse_encoding(argv[++i], &opt->enc)) {
                err(L"错误：不支持的编码“%s”，可用：utf8 / utf8bom / gbk。\n", argv[i]);
                return false;
            }
        } else if (wcscmp(a, L"--keydb") == 0 || wcscmp(a, L"--kugou-dir") == 0) {
            if (i + 1 >= argc) {
                err(L"错误：%s 需要一个路径参数。\n", a);
                print_usage_short();
                return false;
            }
            opt->keydb = argv[++i];
            if (opt->keydb[0] == L'\0') {
                err(L"错误：密钥库路径不能为空。\n");
                return false;
            }
        } else if (wcscmp(a, L"--gui") == 0) {
            err(L"错误：--gui 应在启动参数中单独使用。\n");
            return false;
        } else {
            err(L"错误：未知选项“%s”。\n", a);
            print_usage_short();
            return false;
        }
    }
    if (opt->force_yes && opt->force_no) {
        err(L"错误：-y 与 -n 不能同时使用。\n");
        return false;
    }
    if (opt->path_count == 0) {
        err(L"错误：未指定要转换的文件或目录。\n");
        print_usage_short();
        return false;
    }
    if (opt->keydb) {
        wchar_t *full = GetFullPathDup(opt->keydb);
        if (!full || (!FileExistsW(full) && !IsDirectoryW(full))) {
            err(L"错误：密钥库路径不存在：%s\n", opt->keydb);
            free(full);
            return false;
        }
        free(full);
    }
    return true;
}

static void free_items(ItemList *list)
{
    size_t i;
    for (i = 0; i < list->count; ++i) {
        free(list->items[i].path);
        free(list->items[i].name);
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->cap = 0;
}

static bool add_item(ItemList *list, PathSet *set, const wchar_t *path,
                     uint64_t size)
{
    wchar_t *full = GetFullPathDup(path);
    wchar_t *key;
    TaskItem *it;

    if (!full) return false;
    key = NormalizePathKey(full);
    if (!key) {
        free(full);
        return false;
    }
    if (!PathSet_Add(set, key)) {
        free(key);
        free(full);
        return true;
    }
    free(key);
    if (list->count == list->cap) {
        size_t cap = list->cap ? list->cap * 2 : 64;
        TaskItem *p = (TaskItem *)xrealloc(list->items, cap * sizeof(TaskItem));
        if (!p) {
            free(full);
            return false;
        }
        list->items = p;
        list->cap = cap;
    }
    it = &list->items[list->count];
    memset(it, 0, sizeof(*it));
    it->path = full;
    it->name = xwcsdup(FileNamePtr(full));
    if (!it->name) {
        free(full);
        return false;
    }
    it->size = size;
    it->kind = KindFromPath(full);
    it->status = ST_WAITING;
    it->status_text[0] = L'\0';
    ++list->count;
    return true;
}

static void collect_directory(ItemList *list, PathSet *set,
                              const wchar_t *dir, bool recursive)
{
    wchar_t **stack;
    size_t stack_count = 0;
    size_t stack_cap = 0;
    wchar_t *root = GetFullPathDup(dir);

    if (!root) return;
    stack_cap = 16;
    stack = (wchar_t **)xmalloc(stack_cap * sizeof(wchar_t *));
    if (!stack) {
        free(root);
        return;
    }
    stack[stack_count++] = root;

    while (stack_count > 0) {
        wchar_t *cur = stack[--stack_count];
        wchar_t *pattern = JoinPath(cur, L"*");
        wchar_t *lp = pattern ? MakeLongPath(pattern) : NULL;
        WIN32_FIND_DATAW fd;
        HANDLE find;
        if (!lp) {
            free(pattern);
            free(cur);
            continue;
        }
        find = FindFirstFileW(lp, &fd);
        free(lp);
        free(pattern);
        if (find == INVALID_HANDLE_VALUE) {
            free(cur);
            continue;
        }
        do {
            wchar_t *child;
            uint64_t size;
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) {
                continue;
            }
            child = JoinPath(cur, fd.cFileName);
            if (!child) continue;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (recursive && !(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
                    if (stack_count == stack_cap) {
                        size_t ncap = stack_cap * 2;
                        wchar_t **np = (wchar_t **)xrealloc(stack, ncap * sizeof(wchar_t *));
                        if (np) {
                            stack = np;
                            stack_cap = ncap;
                        }
                    }
                    if (stack_count < stack_cap) {
                        stack[stack_count++] = child;
                        child = NULL;
                    }
                }
            } else if (KindHasSupportedExt(child)) {
                size = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
                add_item(list, set, child, size);
            }
            free(child);
        } while (FindNextFileW(find, &fd));
        FindClose(find);
        free(cur);
    }
    free(stack);
}

static bool collect_inputs(const CliOptions *opt, ItemList *list)
{
    PathSet *set = PathSet_Create();
    int i;
    bool ok = true;

    if (!set) return false;
    for (i = 0; i < opt->path_count; ++i) {
        wchar_t *full = GetFullPathDup(opt->paths[i]);
        bool exists;
        bool is_dir;
        if (!full) {
            err(L"[错误] 无效路径：%s\n", opt->paths[i]);
            g_path_error = true;
            ok = false;
            continue;
        }
        exists = FileExistsW(full);
        is_dir = IsDirectoryW(full);
        if (!exists) {
            err(L"[错误] 路径不存在：%s\n", full);
            free(full);
            g_path_error = true;
            ok = false;
            continue;
        }
        if (is_dir) {
            collect_directory(list, set, full, opt->recursive);
            free(full);
        } else {
            if (!KindHasSupportedExt(full)) {
                err(L"[错误] 不支持的文件类型：%s\n", full);
                free(full);
                g_path_error = true;
                ok = false;
                continue;
            }
            if (!add_item(list, set, full, FileSizeW(full, NULL))) {
                ok = false;
            }
            free(full);
        }
    }
    PathSet_Destroy(set);
    return ok;
}

static int prompt_overwrite(void *ctx, const wchar_t *target)
{
    PromptCtx *p = (PromptCtx *)ctx;
    wchar_t line[128];
    DWORD read = 0;

    if (!p->interactive) {
        out(L"  警告：目标文件已存在，且输入不可交互，已跳过：%s\n", target);
        return 0;
    }
    for (;;) {
        out(L"目标文件已存在：%s\n", target);
        out(L"是否覆盖？[y]是 [n]否 [a]全部是 [s]全部否: ");
        if (!ReadConsoleW(p->input, line, (DWORD)(sizeof(line) / sizeof(line[0])), &read, NULL) ||
            read == 0) {
            out(L"\n");
            return 0;
        }
        {
            size_t j;
            for (j = 0; j < read; ++j) {
                wchar_t c = line[j];
                if (c == L'y' || c == L'Y') return 1;
                if (c == L'n' || c == L'N') return 0;
                if (c == L'a' || c == L'A') return 2;
                if (c == L's' || c == L'S') return 3;
                if (c == L'\r' || c == L'\n') break;
            }
        }
        out(L"请输入 y、n、a 或 s。\n");
    }
}

int CliMain(int argc, wchar_t **argv)
{
    CliOptions opt;
    ItemList list;
    ConvertContext ctx;
    KeyDbCache *keydb = NULL;
    PromptCtx prompt;
    wchar_t *out_dir_full = NULL;
    size_t i;
    size_t success = 0;
    size_t failed = 0;
    size_t skipped = 0;
    bool stopped = false;
    int exit_code = 0;
    DWORD in_mode;

    memset(&list, 0, sizeof(list));
    memset(&ctx, 0, sizeof(ctx));
    memset(&prompt, 0, sizeof(prompt));
    g_stop = 0;
    g_path_error = false;
    g_help = false;

    if (!parse_args(argc, argv, &opt)) {
        int rc = g_help ? 0 : 2;
        free(opt.paths);
        return rc;
    }
    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    if (opt.out_dir) {
        out_dir_full = GetFullPathDup(opt.out_dir);
        if (!out_dir_full) {
            err(L"错误：输出目录无效。\n");
            free(opt.paths);
            return 2;
        }
        {
            wchar_t e[ERR_CAP];
            if (!EnsureDirectoryTree(out_dir_full, e, ERR_CAP)) {
                err(L"错误：%s\n", e);
                free(out_dir_full);
                free(opt.paths);
                return 1;
            }
        }
    }

    if (!collect_inputs(&opt, &list)) {
        if (list.count == 0 && !g_path_error) {
            /* memory failure only */
        }
    }
    if (list.count == 0) {
        if (!g_path_error) err(L"没有找到可转换的文件。\n");
        free_items(&list);
        free(opt.paths);
        free(out_dir_full);
        return 1;
    }

    keydb = KeyDbCache_Create();
    if (!keydb) {
        err(L"错误：内存不足。\n");
        free_items(&list);
        free(opt.paths);
        free(out_dir_full);
        return 1;
    }
    prompt.interactive = GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &in_mode) != 0;
    prompt.input = GetStdHandle(STD_INPUT_HANDLE);

    ctx.opts.enc = opt.enc;
    ctx.opts.out_dir = out_dir_full;
    ctx.opts.keydb = opt.keydb;
    ctx.overwrite = opt.force_yes ? OW_YES_ALL : (opt.force_no ? OW_NO_ALL : OW_ASK);
    ctx.stop = &g_stop;
    ctx.keydb = keydb;
    ctx.prompt_overwrite = prompt_overwrite;
    ctx.prompt_ctx = &prompt;

    for (i = 0; i < list.count; ++i) {
        TaskItem *item = &list.items[i];
        wchar_t out_path[PATH_CAP];
        wchar_t reason[ERR_CAP];
        ConvResult r;
        const wchar_t *status;
        const wchar_t *ext = L"";

        if (InterlockedCompareExchange(&g_stop, 0, 0) != 0) {
            stopped = true;
            break;
        }
        r = ConvertItem(item, &ctx, out_path, PATH_CAP, reason, ERR_CAP);
        if (r == CONV_STOPPED) {
            stopped = true;
            break;
        }
        if (r == CONV_SUCCESS || r == CONV_UNRECOGNIZED) {
            ++success;
            ext = ExtPtr(out_path);
            status = (r == CONV_UNRECOGNIZED) ? L"未识别格式" : L"成功";
        } else if (r == CONV_SKIPPED) {
            ++skipped;
            status = L"已跳过";
        } else {
            ++failed;
            status = L"失败";
        }
        if (r == CONV_SUCCESS) {
            if (opt.verbose) {
                out(L"[%llu/%llu] 成功→%s  %s  ->  %s（源格式：%s）\n",
                    (unsigned long long)(i + 1), (unsigned long long)list.count,
                    ext ? ext : L"", item->name, out_path,
                    KindDisplayName(item->kind));
            } else {
                out(L"[%llu/%llu] 成功→%s  %s\n",
                    (unsigned long long)(i + 1), (unsigned long long)list.count,
                    ext ? ext : L"", item->name);
            }
        } else if (r == CONV_UNRECOGNIZED) {
            if (opt.verbose) {
                out(L"[%llu/%llu] 未识别格式→%s  %s  ->  %s（源格式：%s）\n",
                    (unsigned long long)(i + 1), (unsigned long long)list.count,
                    ext ? ext : L".mp3", item->name, out_path,
                    KindDisplayName(item->kind));
            } else {
                out(L"[%llu/%llu] 未识别格式→%s  %s\n",
                    (unsigned long long)(i + 1), (unsigned long long)list.count,
                    ext ? ext : L".mp3", item->name);
            }
        } else if (r == CONV_SKIPPED) {
            out(L"[%llu/%llu] %s（%s）  %s\n",
                (unsigned long long)(i + 1), (unsigned long long)list.count,
                status, reason[0] ? reason : L"目标文件已存在", item->name);
        } else {
            out(L"[%llu/%llu] 失败（%s）  %s\n",
                (unsigned long long)(i + 1), (unsigned long long)list.count,
                reason[0] ? reason : L"未知错误", item->name);
        }
    }

    if (i < list.count) stopped = true;
    out(L"\n完成：总数 %llu，成功 %llu，失败 %llu，跳过 %llu%s\n",
        (unsigned long long)list.count,
        (unsigned long long)success,
        (unsigned long long)failed,
        (unsigned long long)skipped,
        stopped ? L"，已停止" : L"");
    if (g_path_error) {
        err(L"存在无效的输入路径。\n");
    }
    if (failed > 0 || g_path_error || stopped) {
        exit_code = 1;
    }

    KeyDbCache_Free(keydb);
    free_items(&list);
    free(opt.paths);
    free(out_dir_full);
    return exit_code;
}
