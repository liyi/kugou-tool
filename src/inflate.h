#ifndef KUGOU_TOOL_INFLATE_H
#define KUGOU_TOOL_INFLATE_H

#include "app.h"

bool zlib_decompress(const uint8_t *in, size_t inlen, size_t max_out,
                     uint8_t **out, size_t *outlen,
                     wchar_t *err, size_t errcap);

#endif
