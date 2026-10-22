#ifndef KUGOU_TOOL_KEYDB_H
#define KUGOU_TOOL_KEYDB_H

#include "app.h"

typedef struct KeyDb KeyDb;
typedef struct KeyDbCache KeyDbCache;

KeyDbCache *KeyDbCache_Create(void);
const char *KeyDbCache_Lookup(KeyDbCache *cache, const wchar_t *setting,
                              const char *hash, wchar_t *err, size_t errcap);
void KeyDbCache_Free(KeyDbCache *cache);
wchar_t *KeyDb_AutoDetect(void);

#endif
