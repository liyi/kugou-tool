#ifndef KUGOU_TOOL_CONVERT_H
#define KUGOU_TOOL_CONVERT_H

#include "app.h"
#include "keydb.h"

typedef enum {
    OW_ASK = 0,
    OW_YES_ALL,
    OW_NO_ALL
} OverwriteMode;

typedef struct {
    ConvertOptions opts;
    OverwriteMode overwrite;
    volatile LONG *stop;
    KeyDbCache *keydb;
    int (*prompt_overwrite)(void *ctx, const wchar_t *target);
    void *prompt_ctx;
} ConvertContext;

typedef enum {
    CONV_SUCCESS = 0,
    CONV_UNRECOGNIZED,
    CONV_SKIPPED,
    CONV_FAILED,
    CONV_STOPPED
} ConvResult;

ConvResult ConvertItem(TaskItem *item, ConvertContext *ctx,
                       wchar_t *out_path, size_t out_path_cap,
                       wchar_t *reason, size_t reason_cap);

#endif
