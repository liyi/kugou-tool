#include "gui.h"
#include "convert.h"
#include "keydb.h"
#include "util.h"
#include "resource.h"

#include <commctrl.h>
#include <shobjidl.h>
#include <shellapi.h>
#include <windowsx.h>
#include <strsafe.h>
#include <string.h>

#ifndef WM_DPICHANGED
#define WM_DPICHANGED 0x02E0
#endif

#define WM_APP_ROW (WM_APP + 1)
#define WM_APP_PROGRESS (WM_APP + 2)
#define WM_APP_TASK_DONE (WM_APP + 3)
#define WM_APP_ASK_OVERWRITE (WM_APP + 4)

#define IDC_ADD_FILES 1001
#define IDC_ADD_DIR 1002
#define IDC_RECURSIVE 1003
#define IDC_REMOVE 1004
#define IDC_CLEAR 1005
#define IDC_RADIO_SRC 1010
#define IDC_RADIO_OUT 1011
#define IDC_EDIT_OUT 1012
#define IDC_BROWSE_OUT 1013
#define IDC_LABEL_ENC 1020
#define IDC_COMBO_ENC 1021
#define IDC_LABEL_KEYDB 1022
#define IDC_EDIT_KEYDB 1023
#define IDC_BROWSE_KEYDB 1024
#define IDC_START 1030
#define IDC_STOP 1031
#define IDC_PROGRESS 1032
#define IDC_STATUS 1033
#define IDC_LIST 1034
#define IDC_GROUP_OUT 1035

#define IDM_REMOVE_SEL 2001
#define IDM_REMOVE_DONE 2002

typedef struct OverwriteAsk {
    wchar_t *path;
    int answer;
    HANDLE event;
} OverwriteAsk;

typedef struct {
    HINSTANCE instance;
    HWND hwnd;
    HICON icon;
    HFONT font;
    UINT dpi;

    HWND list;
    HWND add_files;
    HWND add_dir;
    HWND recursive;
    HWND remove;
    HWND clear;
    HWND group_out;
    HWND radio_src;
    HWND radio_out;
    HWND edit_out;
    HWND browse_out;
    HWND label_enc;
    HWND combo_enc;
    HWND label_keydb;
    HWND edit_keydb;
    HWND browse_keydb;
    HWND start;
    HWND stop;
    HWND progress;
    HWND status;

    TaskItem *items;
    size_t count;
    size_t cap;
    PathSet *pathset;

    bool suspend_ui;
    bool running;
    bool closing;
    volatile LONG stop_flag;
    volatile LONG processed;
    volatile LONG success;
    volatile LONG failed;
    volatile LONG skipped;

    HANDLE thread;
    ConvertContext ctx;
    KeyDbCache *keydb;
    wchar_t *task_out_dir;
    wchar_t *task_keydb;
} GuiState;

static GuiState *g_gui;

static int sx(GuiState *g, int value)
{
    return MulDiv(value, (int)g->dpi, 96);
}

static bool is_stopped(GuiState *g)
{
    return InterlockedCompareExchange(&g->stop_flag, 0, 0) != 0;
}

static void update_status_label(GuiState *g)
{
    wchar_t text[256];
    StringCchPrintfW(text, 256, L"共 %llu 个，成功 %ld，失败 %ld，跳过 %ld",
                     (unsigned long long)g->count,
                     (long)InterlockedCompareExchange(&g->success, 0, 0),
                     (long)InterlockedCompareExchange(&g->failed, 0, 0),
                     (long)InterlockedCompareExchange(&g->skipped, 0, 0));
    SetWindowTextW(g->status, text);
}

static void reset_stats(GuiState *g)
{
    InterlockedExchange(&g->processed, 0);
    InterlockedExchange(&g->success, 0);
    InterlockedExchange(&g->failed, 0);
    InterlockedExchange(&g->skipped, 0);
    SendMessageW(g->progress, PBM_SETPOS, 0, 0);
    update_status_label(g);
}

static int selected_count(GuiState *g)
{
    int count = 0;
    int idx = -1;
    for (;;) {
        idx = (int)SendMessageW(g->list, LVM_GETNEXTITEM, (WPARAM)idx, LVNI_SELECTED);
        if (idx < 0) break;
        ++count;
    }
    return count;
}

static bool has_completed(GuiState *g)
{
    size_t i;
    for (i = 0; i < g->count; ++i) {
        if (g->items[i].status == ST_SUCCESS || g->items[i].status == ST_UNRECOGNIZED) {
            return true;
        }
    }
    return false;
}

static void update_ui_state(GuiState *g)
{
    bool busy = g->running;
    bool custom_out;
    bool has_sel;
    if (g->suspend_ui) return;
    custom_out = Button_GetCheck(g->radio_out) == BST_CHECKED;
    has_sel = selected_count(g) > 0;
    EnableWindow(g->add_files, !busy);
    EnableWindow(g->add_dir, !busy);
    EnableWindow(g->recursive, !busy);
    EnableWindow(g->remove, !busy && has_sel);
    EnableWindow(g->clear, !busy && g->count > 0);
    EnableWindow(g->group_out, !busy);
    EnableWindow(g->radio_src, !busy);
    EnableWindow(g->radio_out, !busy);
    EnableWindow(g->edit_out, !busy && custom_out);
    EnableWindow(g->browse_out, !busy && custom_out);
    EnableWindow(g->edit_keydb, !busy);
    EnableWindow(g->browse_keydb, !busy);
    EnableWindow(g->combo_enc, !busy);
    EnableWindow(g->start, !busy && g->count > 0);
    EnableWindow(g->stop, busy);
}

static void set_item_status(GuiState *g, size_t index, ItemStatus status,
                            const wchar_t *text)
{
    if (index >= g->count) return;
    g->items[index].status = status;
    StringCchCopyW(g->items[index].status_text, STATUS_CAP, text ? text : L"");
}

static void insert_row(GuiState *g, size_t index)
{
    LVITEMW it;
    wchar_t sizebuf[64];
    int row;
    TaskItem *item = &g->items[index];
    memset(&it, 0, sizeof(it));
    it.mask = LVIF_TEXT | LVIF_PARAM;
    it.iItem = (int)index;
    it.iSubItem = 0;
    it.pszText = (LPWSTR)item->name;
    it.lParam = (LPARAM)index;
    row = (int)SendMessageW(g->list, LVM_INSERTITEMW, 0, (LPARAM)&it);
    if (row < 0) return;
    FormatSize(item->size, sizebuf, 64);
    SendMessageW(g->list, LVM_SETITEMTEXTW, (WPARAM)row, (LPARAM)&(LVITEMW){
        .iSubItem = 1, .pszText = (LPWSTR)item->path });
    SendMessageW(g->list, LVM_SETITEMTEXTW, (WPARAM)row, (LPARAM)&(LVITEMW){
        .iSubItem = 2, .pszText = sizebuf });
    SendMessageW(g->list, LVM_SETITEMTEXTW, (WPARAM)row, (LPARAM)&(LVITEMW){
        .iSubItem = 3, .pszText = (LPWSTR)item->status_text });
}

static void populate_list(GuiState *g)
{
    bool saved = g->suspend_ui;
    size_t i;
    g->suspend_ui = true;
    SendMessageW(g->list, WM_SETREDRAW, FALSE, 0);
    SendMessageW(g->list, LVM_DELETEALLITEMS, 0, 0);
    for (i = 0; i < g->count; ++i) insert_row(g, i);
    SendMessageW(g->list, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g->list, NULL, TRUE);
    g->suspend_ui = saved;
}

static void rebuild_pathset(GuiState *g)
{
    size_t i;
    if (!g->pathset) return;
    PathSet_Clear(g->pathset);
    for (i = 0; i < g->count; ++i) {
        wchar_t *key = NormalizePathKey(g->items[i].path);
        if (key) {
            PathSet_Add(g->pathset, key);
            free(key);
        }
    }
}

static void begin_bulk(GuiState *g)
{
    g->suspend_ui = true;
    SetCursor(LoadCursorW(NULL, IDC_WAIT));
    SendMessageW(g->list, WM_SETREDRAW, FALSE, 0);
}

static void end_bulk(GuiState *g)
{
    SendMessageW(g->list, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g->list, NULL, TRUE);
    g->suspend_ui = false;
    SetCursor(LoadCursorW(NULL, IDC_ARROW));
    reset_stats(g);
    update_ui_state(g);
}

static bool add_path(GuiState *g, const wchar_t *path, uint64_t size)
{
    wchar_t *full;
    wchar_t *key;
    TaskItem *item;

    if (!KindHasSupportedExt(path)) return true;
    full = GetFullPathDup(path);
    if (!full) return false;
    key = NormalizePathKey(full);
    if (!key) {
        free(full);
        return false;
    }
    if (!PathSet_Add(g->pathset, key)) {
        free(key);
        free(full);
        return true;
    }
    free(key);
    if (g->count == g->cap) {
        size_t cap = g->cap ? g->cap * 2 : 128;
        TaskItem *p;
        if (cap > SIZE_MAX / sizeof(TaskItem)) {
            free(full);
            return false;
        }
        p = (TaskItem *)xrealloc(g->items, cap * sizeof(TaskItem));
        if (!p) {
            free(full);
            return false;
        }
        g->items = p;
        g->cap = cap;
    }
    item = &g->items[g->count];
    memset(item, 0, sizeof(*item));
    item->path = full;
    item->name = xwcsdup(FileNamePtr(full));
    if (!item->name) {
        free(full);
        return false;
    }
    item->size = size;
    item->kind = KindFromPath(full);
    item->status = ST_WAITING;
    StringCchCopyW(item->status_text, STATUS_CAP, L"等待");
    insert_row(g, g->count);
    ++g->count;
    return true;
}

static void scan_directory(GuiState *g, const wchar_t *dir)
{
    bool recursive = Button_GetCheck(g->recursive) == BST_CHECKED;
    wchar_t **stack;
    size_t stack_count = 0;
    size_t stack_cap = 16;
    wchar_t *root = GetFullPathDup(dir);

    if (!root) return;
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
        free(pattern);
        if (!lp) {
            free(cur);
            continue;
        }
        find = FindFirstFileW(lp, &fd);
        free(lp);
        if (find == INVALID_HANDLE_VALUE) {
            free(cur);
            continue;
        }
        do {
            wchar_t *child;
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
                uint64_t size = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
                add_path(g, child, size);
            }
            free(child);
        } while (FindNextFileW(find, &fd));
        FindClose(find);
        free(cur);
    }
    free(stack);
}

/* ---------------- dialogs ---------------- */

static int ask_overwrite_dialog(HWND parent, const wchar_t *path)
{
    TASKDIALOGCONFIG cfg;
    TASKDIALOG_BUTTON buttons[4];
    int pressed = 0;
    HRESULT hr;
    wchar_t shown[512];
    size_t path_len = wcslen(path);

    memset(&cfg, 0, sizeof(cfg));
    memset(buttons, 0, sizeof(buttons));
    buttons[0].nButtonID = 100;
    buttons[0].pszButtonText = L"是(&Y)";
    buttons[1].nButtonID = 101;
    buttons[1].pszButtonText = L"否(&N)";
    buttons[2].nButtonID = 102;
    buttons[2].pszButtonText = L"全部是(&A)";
    buttons[3].nButtonID = 103;
    buttons[3].pszButtonText = L"全部否(&S)";

    cfg.cbSize = sizeof(cfg);
    cfg.hwndParent = parent;
    cfg.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_SIZE_TO_CONTENT |
                  TDF_POSITION_RELATIVE_TO_WINDOW;
    cfg.pszWindowTitle = APP_TITLE;
    cfg.pszMainIcon = TD_WARNING_ICON;
    cfg.pszMainInstruction = L"目标文件已存在";
    if (path_len >= 480) {
        StringCchPrintfW(shown, 512, L"…%s", path + path_len - 460);
    } else {
        StringCchCopyW(shown, 512, path);
    }
    cfg.pszContent = shown;
    cfg.cButtons = 4;
    cfg.pButtons = buttons;
    cfg.nDefaultButton = 100;

    hr = TaskDialogIndirect(&cfg, &pressed, NULL, NULL);
    if (FAILED(hr)) {
        int r = MessageBoxW(parent, path, L"目标文件已存在，是否覆盖？",
                            MB_YESNOCANCEL | MB_ICONWARNING);
        if (r == IDYES) return 1;
        if (r == IDNO) return 0;
        return -1;
    }
    if (pressed == 100) return 1;
    if (pressed == 101) return 0;
    if (pressed == 102) return 2;
    if (pressed == 103) return 3;
    return 0;
}

static int gui_prompt_overwrite(void *context, const wchar_t *target)
{
    GuiState *g = (GuiState *)context;
    OverwriteAsk *ask;
    int answer;

    if (is_stopped(g) || g->closing) return -1;
    ask = (OverwriteAsk *)xcalloc(1, sizeof(OverwriteAsk));
    if (!ask) return 0;
    ask->path = xwcsdup(target);
    ask->event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!ask->path || !ask->event) {
        free(ask->path);
        if (ask->event) CloseHandle(ask->event);
        free(ask);
        return 0;
    }
    if (!PostMessageW(g->hwnd, WM_APP_ASK_OVERWRITE, 0, (LPARAM)ask)) {
        CloseHandle(ask->event);
        free(ask->path);
        free(ask);
        return -1;
    }
    WaitForSingleObject(ask->event, INFINITE);
    answer = ask->answer;
    CloseHandle(ask->event);
    free(ask->path);
    free(ask);
    return answer;
}

static bool choose_files(GuiState *g, const wchar_t *title)
{
    IFileOpenDialog *dialog = NULL;
    HRESULT hr;
    COMDLG_FILTERSPEC specs[4];
    DWORD options = 0;

    specs[0].pszName = L"支持的酷狗文件";
    specs[0].pszSpec = L"*.krc;*.kgg;*.kgma;*.kgm;*.vpr";
    specs[1].pszName = L"歌词文件 (*.krc)";
    specs[1].pszSpec = L"*.krc";
    specs[2].pszName = L"加密音频 (*.kgg;*.kgma;*.kgm;*.vpr)";
    specs[2].pszSpec = L"*.kgg;*.kgma;*.kgm;*.vpr";
    specs[3].pszName = L"所有文件 (*.*)";
    specs[3].pszSpec = L"*.*";

    hr = CoCreateInstance(&CLSID_FileOpenDialog, NULL, CLSCTX_INPROC_SERVER,
                          &IID_IFileOpenDialog, (void **)&dialog);
    if (FAILED(hr) || !dialog) {
        MessageBoxW(g->hwnd, L"无法打开系统文件选择窗口。", APP_TITLE,
                    MB_OK | MB_ICONERROR);
        return false;
    }
    dialog->lpVtbl->GetOptions(dialog, &options);
    dialog->lpVtbl->SetOptions(dialog, options | FOS_ALLOWMULTISELECT |
                                   FOS_FILEMUSTEXIST | FOS_PATHMUSTEXIST |
                                   FOS_FORCEFILESYSTEM);
    dialog->lpVtbl->SetTitle(dialog, title);
    dialog->lpVtbl->SetFileTypes(dialog, 4, specs);
    dialog->lpVtbl->SetFileTypeIndex(dialog, 1);
    hr = dialog->lpVtbl->Show(dialog, g->hwnd);
    if (SUCCEEDED(hr)) {
        IShellItemArray *array = NULL;
        hr = dialog->lpVtbl->GetResults(dialog, &array);
        if (SUCCEEDED(hr) && array) {
            DWORD n = 0;
            DWORD i;
            array->lpVtbl->GetCount(array, &n);
            begin_bulk(g);
            for (i = 0; i < n; ++i) {
                IShellItem *item = NULL;
                if (SUCCEEDED(array->lpVtbl->GetItemAt(array, i, &item)) && item) {
                    PWSTR path = NULL;
                    if (SUCCEEDED(item->lpVtbl->GetDisplayName(item, SIGDN_FILESYSPATH, &path)) && path) {
                        if (KindHasSupportedExt(path)) {
                            add_path(g, path, FileSizeW(path, NULL));
                        }
                        CoTaskMemFree(path);
                    }
                    item->lpVtbl->Release(item);
                }
            }
            end_bulk(g);
            array->lpVtbl->Release(array);
        }
    }
    dialog->lpVtbl->Release(dialog);
    return true;
}

static wchar_t *choose_folder(GuiState *g, const wchar_t *title)
{
    IFileOpenDialog *dialog = NULL;
    HRESULT hr;
    DWORD options = 0;
    wchar_t *result = NULL;

    hr = CoCreateInstance(&CLSID_FileOpenDialog, NULL, CLSCTX_INPROC_SERVER,
                          &IID_IFileOpenDialog, (void **)&dialog);
    if (FAILED(hr) || !dialog) return NULL;
    dialog->lpVtbl->GetOptions(dialog, &options);
    dialog->lpVtbl->SetOptions(dialog, options | FOS_PICKFOLDERS |
                                   FOS_PATHMUSTEXIST | FOS_FORCEFILESYSTEM);
    dialog->lpVtbl->SetTitle(dialog, title);
    hr = dialog->lpVtbl->Show(dialog, g->hwnd);
    if (SUCCEEDED(hr)) {
        IShellItem *item = NULL;
        hr = dialog->lpVtbl->GetResult(dialog, &item);
        if (SUCCEEDED(hr) && item) {
            PWSTR path = NULL;
            if (SUCCEEDED(item->lpVtbl->GetDisplayName(item, SIGDN_FILESYSPATH, &path)) && path) {
                result = xwcsdup(path);
                CoTaskMemFree(path);
            }
            item->lpVtbl->Release(item);
        }
    }
    dialog->lpVtbl->Release(dialog);
    return result;
}

static wchar_t *choose_keydb_file(GuiState *g)
{
    IFileOpenDialog *dialog = NULL;
    HRESULT hr;
    COMDLG_FILTERSPEC specs[2];
    wchar_t *result = NULL;
    DWORD options = 0;

    specs[0].pszName = L"酷狗密钥库 (KGMusicV3.db)";
    specs[0].pszSpec = L"KGMusicV3.db";
    specs[1].pszName = L"所有文件 (*.*)";
    specs[1].pszSpec = L"*.*";

    hr = CoCreateInstance(&CLSID_FileOpenDialog, NULL, CLSCTX_INPROC_SERVER,
                          &IID_IFileOpenDialog, (void **)&dialog);
    if (FAILED(hr) || !dialog) return NULL;
    dialog->lpVtbl->GetOptions(dialog, &options);
    dialog->lpVtbl->SetOptions(dialog, options | FOS_FILEMUSTEXIST |
                                   FOS_PATHMUSTEXIST | FOS_FORCEFILESYSTEM);
    dialog->lpVtbl->SetTitle(dialog, L"选择酷狗密钥库 KGMusicV3.db");
    dialog->lpVtbl->SetFileTypes(dialog, 2, specs);
    hr = dialog->lpVtbl->Show(dialog, g->hwnd);
    if (SUCCEEDED(hr)) {
        IShellItem *item = NULL;
        hr = dialog->lpVtbl->GetResult(dialog, &item);
        if (SUCCEEDED(hr) && item) {
            PWSTR path = NULL;
            if (SUCCEEDED(item->lpVtbl->GetDisplayName(item, SIGDN_FILESYSPATH, &path)) && path) {
                result = xwcsdup(path);
                CoTaskMemFree(path);
            }
            item->lpVtbl->Release(item);
        }
    }
    dialog->lpVtbl->Release(dialog);
    return result;
}

/* ---------------- task ---------------- */

static void worker_set_status(GuiState *g, size_t index, ConvResult r,
                              const wchar_t *out_path, const wchar_t *reason)
{
    wchar_t text[STATUS_CAP];
    ItemStatus st;

    switch (r) {
    case CONV_SUCCESS:
        st = ST_SUCCESS;
        StringCchPrintfW(text, STATUS_CAP, L"成功→%s", ExtPtr(out_path) ? ExtPtr(out_path) : L"");
        InterlockedIncrement(&g->success);
        break;
    case CONV_UNRECOGNIZED:
        st = ST_UNRECOGNIZED;
        StringCchPrintfW(text, STATUS_CAP, L"未识别格式→%s", ExtPtr(out_path) ? ExtPtr(out_path) : L".mp3");
        InterlockedIncrement(&g->success);
        break;
    case CONV_SKIPPED:
        st = ST_SKIPPED;
        StringCchCopyW(text, STATUS_CAP, L"已跳过");
        InterlockedIncrement(&g->skipped);
        break;
    default:
        st = ST_FAILED;
        if (reason && reason[0]) {
            StringCchPrintfW(text, STATUS_CAP, L"失败：%s", reason);
        } else {
            StringCchCopyW(text, STATUS_CAP, L"失败");
        }
        InterlockedIncrement(&g->failed);
        break;
    }
    set_item_status(g, index, st, text);
}

static DWORD WINAPI worker_thread(void *param)
{
    GuiState *g = (GuiState *)param;
    size_t i;
    for (i = 0; i < g->count; ++i) {
        wchar_t out_path[PATH_CAP];
        wchar_t reason[ERR_CAP];
        ConvResult r;
        if (is_stopped(g)) break;
        set_item_status(g, i, ST_RUNNING, L"转换中");
        PostMessageW(g->hwnd, WM_APP_ROW, (WPARAM)i, 0);
        r = ConvertItem(&g->items[i], &g->ctx, out_path, PATH_CAP, reason, ERR_CAP);
        if (r == CONV_STOPPED) {
            set_item_status(g, i, ST_WAITING, L"等待");
            PostMessageW(g->hwnd, WM_APP_ROW, (WPARAM)i, 0);
            break;
        }
        worker_set_status(g, i, r, out_path, reason);
        InterlockedIncrement(&g->processed);
        PostMessageW(g->hwnd, WM_APP_ROW, (WPARAM)i, 0);
        PostMessageW(g->hwnd, WM_APP_PROGRESS, 0, 0);
    }
    PostMessageW(g->hwnd, WM_APP_TASK_DONE, 0, 0);
    return 0;
}

static void free_task_options(GuiState *g)
{
    free(g->task_out_dir);
    g->task_out_dir = NULL;
    free(g->task_keydb);
    g->task_keydb = NULL;
}

static void start_task(GuiState *g)
{
    wchar_t out_text[PATH_CAP];
    wchar_t key_text[PATH_CAP];
    wchar_t err[ERR_CAP];
    wchar_t *out_dir = NULL;
    wchar_t *keydb = NULL;
    LrcEncoding enc;
    size_t i;

    if (g->running || g->count == 0) return;
    if (Button_GetCheck(g->radio_out) == BST_CHECKED) {
        GetWindowTextW(g->edit_out, out_text, PATH_CAP);
        {
            wchar_t *trimmed = TrimW(out_text);
            if (!trimmed[0]) {
                MessageBoxW(g->hwnd, L"请选择或填写输出目录。", APP_TITLE,
                            MB_OK | MB_ICONINFORMATION);
                return;
            }
            out_dir = GetFullPathDup(trimmed);
            if (!out_dir) {
                MessageBoxW(g->hwnd, L"输出目录无效。", APP_TITLE,
                            MB_OK | MB_ICONERROR);
                return;
            }
            if (!EnsureDirectoryTree(out_dir, err, ERR_CAP)) {
                MessageBoxW(g->hwnd, err, APP_TITLE, MB_OK | MB_ICONERROR);
                free(out_dir);
                return;
            }
        }
    }
    GetWindowTextW(g->edit_keydb, key_text, PATH_CAP);
    {
        wchar_t *trimmed = TrimW(key_text);
        if (trimmed[0]) {
            keydb = xwcsdup(trimmed);
            if (!keydb) {
                free(out_dir);
                MessageBoxW(g->hwnd, L"内存不足。", APP_TITLE, MB_OK | MB_ICONERROR);
                return;
            }
        }
    }
    switch (ComboBox_GetCurSel(g->combo_enc)) {
    case 1: enc = ENC_UTF8; break;
    case 2: enc = ENC_GBK; break;
    default: enc = ENC_UTF8_BOM; break;
    }

    free_task_options(g);
    g->task_out_dir = out_dir;
    g->task_keydb = keydb;
    g->keydb = KeyDbCache_Create();
    if (!g->keydb) {
        free_task_options(g);
        MessageBoxW(g->hwnd, L"内存不足。", APP_TITLE, MB_OK | MB_ICONERROR);
        return;
    }
    InterlockedExchange(&g->stop_flag, 0);
    InterlockedExchange(&g->processed, 0);
    InterlockedExchange(&g->success, 0);
    InterlockedExchange(&g->failed, 0);
    InterlockedExchange(&g->skipped, 0);
    g->running = true;
    g->closing = false;
    for (i = 0; i < g->count; ++i) {
        g->items[i].status = ST_WAITING;
        StringCchCopyW(g->items[i].status_text, STATUS_CAP, L"等待");
    }
    populate_list(g);
    SendMessageW(g->progress, PBM_SETRANGE32, 0, (LPARAM)g->count);
    SendMessageW(g->progress, PBM_SETPOS, 0, 0);
    update_status_label(g);

    memset(&g->ctx, 0, sizeof(g->ctx));
    g->ctx.opts.enc = enc;
    g->ctx.opts.out_dir = g->task_out_dir;
    g->ctx.opts.keydb = g->task_keydb;
    g->ctx.overwrite = OW_ASK;
    g->ctx.stop = &g->stop_flag;
    g->ctx.keydb = g->keydb;
    g->ctx.prompt_overwrite = gui_prompt_overwrite;
    g->ctx.prompt_ctx = g;

    update_ui_state(g);
    g->thread = CreateThread(NULL, 0, worker_thread, g, 0, NULL);
    if (!g->thread) {
        g->running = false;
        KeyDbCache_Free(g->keydb);
        g->keydb = NULL;
        free_task_options(g);
        MessageBoxW(g->hwnd, L"无法创建后台转换线程。", APP_TITLE,
                    MB_OK | MB_ICONERROR);
        update_ui_state(g);
    }
}

/* ---------------- item removal ---------------- */

static void remove_indices(GuiState *g, const bool *keep)
{
    size_t i;
    size_t w = 0;
    for (i = 0; i < g->count; ++i) {
        if (keep[i]) {
            if (w != i) g->items[w] = g->items[i];
            ++w;
        } else {
            free(g->items[i].path);
            free(g->items[i].name);
        }
    }
    g->count = w;
    rebuild_pathset(g);
    populate_list(g);
    reset_stats(g);
    update_ui_state(g);
}

static void remove_selected(GuiState *g)
{
    bool *keep;
    int idx;
    if (g->running || g->count == 0) return;
    keep = (bool *)xmalloc(g->count * sizeof(bool));
    if (!keep) return;
    {
        size_t i;
        for (i = 0; i < g->count; ++i) keep[i] = true;
    }
    idx = -1;
    for (;;) {
        idx = (int)SendMessageW(g->list, LVM_GETNEXTITEM, (WPARAM)idx, LVNI_SELECTED);
        if (idx < 0) break;
        if ((size_t)idx < g->count) keep[idx] = false;
    }
    remove_indices(g, keep);
    free(keep);
}

static void remove_completed(GuiState *g)
{
    bool *keep;
    size_t i;
    if (g->running || g->count == 0) return;
    keep = (bool *)xmalloc(g->count * sizeof(bool));
    if (!keep) return;
    for (i = 0; i < g->count; ++i) {
        keep[i] = !(g->items[i].status == ST_SUCCESS ||
                    g->items[i].status == ST_UNRECOGNIZED);
    }
    remove_indices(g, keep);
    free(keep);
}

static void clear_all(GuiState *g)
{
    size_t i;
    if (g->running) return;
    for (i = 0; i < g->count; ++i) {
        free(g->items[i].path);
        free(g->items[i].name);
    }
    g->count = 0;
    PathSet_Clear(g->pathset);
    SendMessageW(g->list, LVM_DELETEALLITEMS, 0, 0);
    reset_stats(g);
    update_ui_state(g);
}

/* ---------------- layout ---------------- */

static void layout_controls(GuiState *g)
{
    RECT rc;
    int w, h, m, gap, bh, list_y, list_h, bottom_h;
    int out_y, settings_y, btn_y;
    int col_name, col_size, col_status, col_path, list_w;

    GetClientRect(g->hwnd, &rc);
    w = rc.right;
    h = rc.bottom;
    m = sx(g, 12);
    gap = sx(g, 8);
    bh = sx(g, 30);

    MoveWindow(g->add_files, m, m, sx(g, 100), bh, TRUE);
    MoveWindow(g->add_dir, m + sx(g, 108), m, sx(g, 100), bh, TRUE);
    MoveWindow(g->recursive, m + sx(g, 216), m + sx(g, 2), sx(g, 130), sx(g, 24), TRUE);
    MoveWindow(g->remove, m + sx(g, 354), m, sx(g, 100), bh, TRUE);
    MoveWindow(g->clear, m + sx(g, 462), m, sx(g, 100), bh, TRUE);

    list_y = m + bh + gap;
    bottom_h = sx(g, 190);
    list_h = h - list_y - bottom_h - m;
    if (list_h < sx(g, 120)) list_h = sx(g, 120);
    MoveWindow(g->list, m, list_y, w - 2 * m, list_h, TRUE);

    out_y = h - bottom_h;
    MoveWindow(g->group_out, m, out_y, w - 2 * m, sx(g, 92), TRUE);
    MoveWindow(g->radio_src, m + sx(g, 14), out_y + sx(g, 22), sx(g, 240), sx(g, 24), TRUE);
    MoveWindow(g->radio_out, m + sx(g, 14), out_y + sx(g, 55), sx(g, 110), sx(g, 24), TRUE);
    MoveWindow(g->edit_out, m + sx(g, 130), out_y + sx(g, 53),
               w - 2 * m - sx(g, 130) - sx(g, 100) - sx(g, 28), sx(g, 26), TRUE);
    MoveWindow(g->browse_out, w - m - sx(g, 100) - sx(g, 14), out_y + sx(g, 52),
               sx(g, 100), sx(g, 28), TRUE);

    settings_y = h - sx(g, 92);
    MoveWindow(g->label_enc, m, settings_y + sx(g, 6), sx(g, 80), sx(g, 24), TRUE);
    MoveWindow(g->combo_enc, m + sx(g, 84), settings_y + sx(g, 3), sx(g, 160), sx(g, 200), TRUE);
    MoveWindow(g->label_keydb, m + sx(g, 258), settings_y + sx(g, 6), sx(g, 70), sx(g, 24), TRUE);
    MoveWindow(g->edit_keydb, m + sx(g, 330), settings_y + sx(g, 3),
               w - 2 * m - sx(g, 330) - sx(g, 100) - sx(g, 14), sx(g, 26), TRUE);
    MoveWindow(g->browse_keydb, w - m - sx(g, 100) - sx(g, 14), settings_y + sx(g, 2),
               sx(g, 100), sx(g, 28), TRUE);

    btn_y = h - sx(g, 54);
    MoveWindow(g->start, m, btn_y, sx(g, 100), sx(g, 32), TRUE);
    MoveWindow(g->stop, m + sx(g, 108), btn_y, sx(g, 100), sx(g, 32), TRUE);
    MoveWindow(g->progress, m + sx(g, 220), btn_y + sx(g, 7),
               w - 2 * m - sx(g, 220), sx(g, 18), TRUE);
    MoveWindow(g->status, m, h - sx(g, 20), w - 2 * m, sx(g, 18), TRUE);

    list_w = w - 2 * m - GetSystemMetrics(SM_CXVSCROLL) - sx(g, 4);
    col_name = sx(g, 230);
    col_size = sx(g, 90);
    col_status = sx(g, 240);
    col_path = list_w - col_name - col_size - col_status;
    if (col_path < sx(g, 120)) col_path = sx(g, 120);
    SendMessageW(g->list, LVM_SETCOLUMNWIDTH, 0, MAKELPARAM(col_name, 0));
    SendMessageW(g->list, LVM_SETCOLUMNWIDTH, 1, MAKELPARAM(col_path, 0));
    SendMessageW(g->list, LVM_SETCOLUMNWIDTH, 2, MAKELPARAM(col_size, 0));
    SendMessageW(g->list, LVM_SETCOLUMNWIDTH, 3, MAKELPARAM(col_status, 0));
}

static BOOL CALLBACK set_font_proc(HWND child, LPARAM font)
{
    SendMessageW(child, WM_SETFONT, (WPARAM)font, TRUE);
    return TRUE;
}

static void create_font(GuiState *g)
{
    HFONT old = g->font;
    g->font = CreateFontW(-MulDiv(9, (int)g->dpi, 72), 0, 0, 0, FW_NORMAL,
                          FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                          OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                          CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE,
                          L"Segoe UI");
    if (g->font) {
        EnumChildWindows(g->hwnd, set_font_proc, (LPARAM)g->font);
    } else {
        g->font = old;
        return;
    }
    if (old) DeleteObject(old);
}

static void add_columns(GuiState *g)
{
    static const wchar_t *names[] = { L"文件名", L"路径", L"大小", L"状态" };
    int i;
    for (i = 0; i < 4; ++i) {
        LVCOLUMNW col;
        memset(&col, 0, sizeof(col));
        col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        col.pszText = (LPWSTR)names[i];
        col.cx = sx(g, i == 1 ? 400 : (i == 2 ? 90 : 230));
        col.iSubItem = i;
        SendMessageW(g->list, LVM_INSERTCOLUMNW, (WPARAM)i, (LPARAM)&col);
    }
}

/* ---------------- window proc ---------------- */

static void show_context_menu(GuiState *g, int x, int y)
{
    HMENU menu;
    int command;
    bool busy = g->running;
    if (busy) return;
    menu = CreatePopupMenu();
    if (!menu) return;
    AppendMenuW(menu, MF_STRING, IDM_REMOVE_SEL, L"移除选中");
    AppendMenuW(menu, MF_STRING, IDM_REMOVE_DONE, L"移除已完成");
    EnableMenuItem(menu, IDM_REMOVE_SEL, MF_BYCOMMAND |
                   (selected_count(g) > 0 ? MF_ENABLED : MF_GRAYED));
    EnableMenuItem(menu, IDM_REMOVE_DONE, MF_BYCOMMAND |
                   (has_completed(g) ? MF_ENABLED : MF_GRAYED));
    command = (int)TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_RETURNCMD,
                                  x, y, 0, g->hwnd, NULL);
    DestroyMenu(menu);
    if (command == IDM_REMOVE_SEL) remove_selected(g);
    if (command == IDM_REMOVE_DONE) remove_completed(g);
}

static LRESULT handle_custom_draw(GuiState *g, NMLVCUSTOMDRAW *cd)
{
    if (cd->nmcd.dwDrawStage == CDDS_PREPAINT) {
        return CDRF_NOTIFYITEMDRAW;
    }
    if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
        return CDRF_NOTIFYSUBITEMDRAW;
    }
    if (cd->nmcd.dwDrawStage == (CDDS_ITEMPREPAINT | CDDS_SUBITEM)) {
        size_t index = (size_t)cd->nmcd.dwItemSpec;
        if (cd->iSubItem == 3 && index < g->count &&
            !(cd->nmcd.uItemState & CDIS_SELECTED)) {
            switch (g->items[index].status) {
            case ST_SUCCESS:
                cd->clrText = RGB(0, 120, 0);
                break;
            case ST_UNRECOGNIZED:
                cd->clrText = RGB(180, 90, 0);
                break;
            case ST_FAILED:
                cd->clrText = RGB(190, 0, 0);
                break;
            case ST_RUNNING:
                cd->clrText = RGB(0, 70, 190);
                break;
            case ST_SKIPPED:
                cd->clrText = RGB(120, 120, 120);
                break;
            default:
                break;
            }
            return CDRF_NEWFONT;
        }
    }
    return CDRF_DODEFAULT;
}

static LRESULT CALLBACK window_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    GuiState *g = g_gui;

    switch (msg) {
    case WM_CREATE:
        g->hwnd = hwnd;
        g->pathset = PathSet_Create();
        g->add_files = CreateWindowExW(0, L"BUTTON", L"添加文件",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, 0, 0, hwnd, (HMENU)IDC_ADD_FILES, g->instance, NULL);
        g->add_dir = CreateWindowExW(0, L"BUTTON", L"添加目录",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, 0, 0, hwnd, (HMENU)IDC_ADD_DIR, g->instance, NULL);
        g->recursive = CreateWindowExW(0, L"BUTTON", L"包含子目录",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
            0, 0, 0, 0, hwnd, (HMENU)IDC_RECURSIVE, g->instance, NULL);
        Button_SetCheck(g->recursive, BST_CHECKED);
        g->remove = CreateWindowExW(0, L"BUTTON", L"移除选中",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, 0, 0, hwnd, (HMENU)IDC_REMOVE, g->instance, NULL);
        g->clear = CreateWindowExW(0, L"BUTTON", L"清空列表",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, 0, 0, hwnd, (HMENU)IDC_CLEAR, g->instance, NULL);

        g->list = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT |
                LVS_SHOWSELALWAYS,
            0, 0, 0, 0, hwnd, (HMENU)IDC_LIST, g->instance, NULL);
        if (g->list) {
            ListView_SetExtendedListViewStyle(g->list,
                LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES |
                LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
            add_columns(g);
        }

        g->group_out = CreateWindowExW(0, L"BUTTON", L"输出目录",
            WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
            0, 0, 0, 0, hwnd, (HMENU)IDC_GROUP_OUT, g->instance, NULL);
        g->radio_src = CreateWindowExW(0, L"BUTTON", L"输出到原文件所在目录",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTORADIOBUTTON | WS_GROUP,
            0, 0, 0, 0, hwnd, (HMENU)IDC_RADIO_SRC, g->instance, NULL);
        g->radio_out = CreateWindowExW(0, L"BUTTON", L"指定输出目录：",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTORADIOBUTTON,
            0, 0, 0, 0, hwnd, (HMENU)IDC_RADIO_OUT, g->instance, NULL);
        Button_SetCheck(g->radio_src, BST_CHECKED);
        g->edit_out = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 0, 0, hwnd, (HMENU)IDC_EDIT_OUT, g->instance, NULL);
        g->browse_out = CreateWindowExW(0, L"BUTTON", L"浏览…",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, 0, 0, hwnd, (HMENU)IDC_BROWSE_OUT, g->instance, NULL);

        g->label_enc = CreateWindowExW(0, L"STATIC", L"LRC 编码：",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            0, 0, 0, 0, hwnd, (HMENU)IDC_LABEL_ENC, g->instance, NULL);
        g->combo_enc = CreateWindowExW(0, L"COMBOBOX", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
            0, 0, 0, 0, hwnd, (HMENU)IDC_COMBO_ENC, g->instance, NULL);
        ComboBox_AddString(g->combo_enc, L"UTF-8（带 BOM）");
        ComboBox_AddString(g->combo_enc, L"UTF-8（无 BOM）");
        ComboBox_AddString(g->combo_enc, L"GBK");
        ComboBox_SetCurSel(g->combo_enc, 0);

        g->label_keydb = CreateWindowExW(0, L"STATIC", L"密钥库：",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            0, 0, 0, 0, hwnd, (HMENU)IDC_LABEL_KEYDB, g->instance, NULL);
        g->edit_keydb = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
            0, 0, 0, 0, hwnd, (HMENU)IDC_EDIT_KEYDB, g->instance, NULL);
        g->browse_keydb = CreateWindowExW(0, L"BUTTON", L"浏览…",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, 0, 0, hwnd, (HMENU)IDC_BROWSE_KEYDB, g->instance, NULL);
        SendMessageW(g->edit_keydb, EM_SETCUEBANNER, TRUE,
                     (LPARAM)L"留空自动检测 KGMusicV3.db");
        SendMessageW(g->edit_out, EM_SETCUEBANNER, TRUE,
                     (LPARAM)L"例如：D:\\转换输出");

        g->start = CreateWindowExW(0, L"BUTTON", L"开始转换",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, 0, 0, hwnd, (HMENU)IDC_START, g->instance, NULL);
        g->stop = CreateWindowExW(0, L"BUTTON", L"停止",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, 0, 0, hwnd, (HMENU)IDC_STOP, g->instance, NULL);
        g->progress = CreateWindowExW(0, PROGRESS_CLASSW, L"",
            WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
            0, 0, 0, 0, hwnd, (HMENU)IDC_PROGRESS, g->instance, NULL);
        g->status = CreateWindowExW(0, L"STATIC", L"",
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
            0, 0, 0, 0, hwnd, (HMENU)IDC_STATUS, g->instance, NULL);

        if (!g->list || !g->start || !g->status) return -1;
        create_font(g);
        layout_controls(g);
        DragAcceptFiles(hwnd, TRUE);
        SendMessageW(g->progress, PBM_SETRANGE32, 0, 1);
        update_status_label(g);
        update_ui_state(g);
        SendMessageW(g->hwnd, WM_SETICON, ICON_BIG, (LPARAM)g->icon);
        SendMessageW(g->hwnd, WM_SETICON, ICON_SMALL, (LPARAM)g->icon);
        return 0;

    case WM_SIZE:
        if (g && wParam != SIZE_MINIMIZED) layout_controls(g);
        return 0;

    case WM_GETMINMAXINFO:
        if (g) {
            MINMAXINFO *mmi = (MINMAXINFO *)lParam;
            RECT r;
            r.left = 0;
            r.top = 0;
            r.right = sx(g, 900);
            r.bottom = sx(g, 500);
            AdjustWindowRectEx(&r, (DWORD)GetWindowLongPtrW(hwnd, GWL_STYLE), FALSE,
                               (DWORD)GetWindowLongPtrW(hwnd, GWL_EXSTYLE));
            mmi->ptMinTrackSize.x = r.right - r.left;
            mmi->ptMinTrackSize.y = r.bottom - r.top;
        }
        return 0;

    case WM_DPICHANGED:
        if (g) {
            RECT *suggested = (RECT *)lParam;
            g->dpi = (UINT)HIWORD(wParam);
            SetWindowPos(hwnd, NULL, suggested->left, suggested->top,
                         suggested->right - suggested->left,
                         suggested->bottom - suggested->top,
                         SWP_NOZORDER | SWP_NOACTIVATE);
            create_font(g);
            layout_controls(g);
        }
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_ADD_FILES:
            choose_files(g, L"选择酷狗文件");
            return 0;
        case IDC_ADD_DIR: {
            wchar_t *folder = choose_folder(g, L"选择要转换的文件夹");
            if (folder) {
                begin_bulk(g);
                scan_directory(g, folder);
                end_bulk(g);
                free(folder);
            }
            return 0;
        }
        case IDC_RECURSIVE:
            return 0;
        case IDC_REMOVE:
            remove_selected(g);
            return 0;
        case IDC_CLEAR:
            clear_all(g);
            return 0;
        case IDC_RADIO_SRC:
        case IDC_RADIO_OUT:
            update_ui_state(g);
            return 0;
        case IDC_BROWSE_OUT: {
            wchar_t *folder = choose_folder(g, L"选择输出目录");
            if (folder) {
                SetWindowTextW(g->edit_out, folder);
                Button_SetCheck(g->radio_out, BST_CHECKED);
                update_ui_state(g);
                free(folder);
            }
            return 0;
        }
        case IDC_BROWSE_KEYDB: {
            wchar_t *file = choose_keydb_file(g);
            if (file) {
                SetWindowTextW(g->edit_keydb, file);
                free(file);
            }
            return 0;
        }
        case IDC_START:
            start_task(g);
            return 0;
        case IDC_STOP:
            if (g->running) InterlockedExchange(&g->stop_flag, 1);
            return 0;
        default:
            break;
        }
        break;

    case WM_NOTIFY:
        if (g && ((NMHDR *)lParam)->hwndFrom == g->list) {
            NMHDR *hdr = (NMHDR *)lParam;
            if (hdr->code == LVN_KEYDOWN) {
                NMLVKEYDOWN *key = (NMLVKEYDOWN *)lParam;
                if (key->wVKey == VK_DELETE && !g->running) remove_selected(g);
                return 0;
            }
            if (hdr->code == LVN_ITEMCHANGED) {
                update_ui_state(g);
                return 0;
            }
            if (hdr->code == NM_CUSTOMDRAW) {
                return handle_custom_draw(g, (NMLVCUSTOMDRAW *)lParam);
            }
        }
        break;

    case WM_CONTEXTMENU:
        if (g && (HWND)wParam == g->list) {
            int x = GET_X_LPARAM(lParam);
            int y = GET_Y_LPARAM(lParam);
            LVHITTESTINFO hit;
            memset(&hit, 0, sizeof(hit));
            hit.pt.x = x;
            hit.pt.y = y;
            ScreenToClient(g->list, &hit.pt);
            if (SendMessageW(g->list, LVM_HITTEST, 0, (LPARAM)&hit) >= 0) {
                if (!(hit.flags & LVHT_ONITEM)) return 0;
                if (!(ListView_GetItemState(g->list, hit.iItem, LVIS_SELECTED) & LVIS_SELECTED)) {
                    ListView_SetItemState(g->list, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
                    ListView_SetItemState(g->list, hit.iItem,
                                          LVIS_SELECTED | LVIS_FOCUSED,
                                          LVIS_SELECTED | LVIS_FOCUSED);
                }
                show_context_menu(g, x, y);
            }
            return 0;
        }
        break;

    case WM_DROPFILES:
        if (g) {
            HDROP drop = (HDROP)wParam;
            UINT n;
            UINT i;
            if (g->running) {
                DragFinish(drop);
                return 0;
            }
            n = DragQueryFileW(drop, 0xFFFFFFFF, NULL, 0);
            begin_bulk(g);
            for (i = 0; i < n; ++i) {
                wchar_t path[PATH_CAP];
                UINT len = DragQueryFileW(drop, i, path, PATH_CAP);
                if (len > 0 && len < PATH_CAP) {
                    if (IsDirectoryW(path)) {
                        scan_directory(g, path);
                    } else if (FileExistsW(path) && KindHasSupportedExt(path)) {
                        add_path(g, path, FileSizeW(path, NULL));
                    }
                }
            }
            end_bulk(g);
            DragFinish(drop);
            return 0;
        }
        break;

    case WM_APP_ROW: {
        size_t index = (size_t)wParam;
        if (g && index < g->count) {
            LVITEMW it;
            memset(&it, 0, sizeof(it));
            it.iSubItem = 3;
            it.pszText = g->items[index].status_text;
            SendMessageW(g->list, LVM_SETITEMTEXTW, (WPARAM)index, (LPARAM)&it);
            InvalidateRect(g->list, NULL, FALSE);
        }
        return 0;
    }

    case WM_APP_PROGRESS:
        if (g) {
            LONG processed = InterlockedCompareExchange(&g->processed, 0, 0);
            SendMessageW(g->progress, PBM_SETPOS, (WPARAM)processed, 0);
            update_status_label(g);
        }
        return 0;

    case WM_APP_ASK_OVERWRITE: {
        OverwriteAsk *ask = (OverwriteAsk *)lParam;
        if (ask) {
            if (!g || g->closing || is_stopped(g)) {
                ask->answer = -1;
            } else {
                ask->answer = ask_overwrite_dialog(g->hwnd, ask->path);
            }
            SetEvent(ask->event);
        }
        return 0;
    }

    case WM_APP_TASK_DONE:
        if (g) {
            LONG processed;
            LONG success;
            LONG failed;
            LONG skipped;
            if (g->thread) {
                WaitForSingleObject(g->thread, INFINITE);
                CloseHandle(g->thread);
                g->thread = NULL;
            }
            g->running = false;
            if (g->keydb) {
                KeyDbCache_Free(g->keydb);
                g->keydb = NULL;
            }
            free_task_options(g);
            processed = InterlockedCompareExchange(&g->processed, 0, 0);
            success = InterlockedCompareExchange(&g->success, 0, 0);
            failed = InterlockedCompareExchange(&g->failed, 0, 0);
            skipped = InterlockedCompareExchange(&g->skipped, 0, 0);
            SendMessageW(g->progress, PBM_SETPOS, (WPARAM)processed, 0);
            update_status_label(g);
            update_ui_state(g);
            if (!g->closing) {
                wchar_t text[512];
                bool stopped = ((size_t)processed < g->count);
                StringCchPrintfW(text, 512,
                                 L"总数：%llu\r\n成功：%ld\r\n失败：%ld\r\n跳过：%ld",
                                 (unsigned long long)g->count,
                                 (long)success, (long)failed, (long)skipped);
                MessageBoxW(g->hwnd, text,
                            stopped ? L"转换已停止" : L"转换完成",
                            MB_OK | MB_ICONINFORMATION);
            } else {
                DestroyWindow(g->hwnd);
            }
        }
        return 0;

    case WM_CLOSE:
        if (g && g->running) {
            int answer = MessageBoxW(g->hwnd, L"转换正在进行，是否停止并退出？",
                                     APP_TITLE, MB_YESNO | MB_ICONQUESTION);
            if (answer != IDYES) return 0;
            g->closing = true;
            InterlockedExchange(&g->stop_flag, 1);
            return 0;
        }
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        if (g) {
            InterlockedExchange(&g->stop_flag, 1);
            if (g->thread) {
                WaitForSingleObject(g->thread, INFINITE);
                CloseHandle(g->thread);
                g->thread = NULL;
            }
            if (g->keydb) {
                KeyDbCache_Free(g->keydb);
                g->keydb = NULL;
            }
            free_task_options(g);
            if (g->pathset) {
                PathSet_Destroy(g->pathset);
                g->pathset = NULL;
            }
            {
                size_t i;
                for (i = 0; i < g->count; ++i) {
                    free(g->items[i].path);
                    free(g->items[i].name);
                }
            }
            free(g->items);
            g->items = NULL;
            g->count = 0;
            g->cap = 0;
            if (g->font) {
                DeleteObject(g->font);
                g->font = NULL;
            }
        }
        g_gui = NULL;
        PostQuitMessage(0);
        return 0;

    default:
        break;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static UINT initial_dpi(void)
{
    HDC dc = GetDC(NULL);
    UINT dpi = 96;
    if (dc) {
        dpi = (UINT)GetDeviceCaps(dc, LOGPIXELSX);
        ReleaseDC(NULL, dc);
    }
    if (dpi < 72 || dpi > 480) dpi = 96;
    return dpi;
}

int GuiMain(HINSTANCE instance, int nCmdShow)
{
    WNDCLASSEXW wc;
    GuiState state;
    HWND hwnd;
    MSG msg;
    HICON icon;
    RECT work;
    int width, height;
    HRESULT co;
    bool co_ok = false;
    INITCOMMONCONTROLSEX icc;

    memset(&state, 0, sizeof(state));
    state.instance = instance;
    state.dpi = initial_dpi();
    state.stop_flag = 0;
    state.processed = 0;
    state.success = 0;
    state.failed = 0;
    state.skipped = 0;
    g_gui = &state;

    co = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    if (SUCCEEDED(co)) co_ok = true;

    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_WIN95_CLASSES | ICC_LISTVIEW_CLASSES |
                ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    icon = LoadIconW(instance, MAKEINTRESOURCEW(IDI_APP_ICON));
    if (!icon) icon = LoadIconW(NULL, IDI_APPLICATION);
    state.icon = icon;

    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = window_proc;
    wc.hInstance = instance;
    wc.hIcon = icon;
    wc.hIconSm = icon;
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"KugouFileToolWindow";
    if (!RegisterClassExW(&wc)) {
        if (co_ok) CoUninitialize();
        return 1;
    }

    width = sx(&state, 1100);
    height = sx(&state, 720);
    {
        RECT r = { 0, 0, width, height };
        AdjustWindowRectEx(&r, WS_OVERLAPPEDWINDOW, FALSE, 0);
        width = r.right - r.left;
        height = r.bottom - r.top;
    }
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
    if (width > work.right - work.left - 20) width = work.right - work.left - 20;
    if (height > work.bottom - work.top - 20) height = work.bottom - work.top - 20;
    if (width < sx(&state, 720)) width = sx(&state, 720);
    if (height < sx(&state, 500)) height = sx(&state, 500);

    hwnd = CreateWindowExW(0, wc.lpszClassName, APP_TITLE,
                           WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                           (work.left + (work.right - work.left - width) / 2),
                           (work.top + (work.bottom - work.top - height) / 2),
                           width, height, NULL, NULL, instance, NULL);
    if (!hwnd) {
        if (co_ok) CoUninitialize();
        return 1;
    }
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        if (!IsDialogMessageW(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    if (co_ok) CoUninitialize();
    return 0;
}
