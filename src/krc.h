#ifndef KUGOU_TOOL_KRC_H
#define KUGOU_TOOL_KRC_H

#include "app.h"

bool KrcMagicOk(const uint8_t *data, size_t len);
bool KrcToLrc(const uint8_t *data, size_t len, LrcEncoding enc,
              uint8_t **out, size_t *outlen, wchar_t *err, size_t errcap);

#endif
