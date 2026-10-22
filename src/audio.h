#ifndef KUGOU_TOOL_AUDIO_H
#define KUGOU_TOOL_AUDIO_H

#include "app.h"
#include "keydb.h"

typedef struct AudioDecryptor AudioDecryptor;

bool AudioMagicOk(const uint8_t *data, size_t len);

AudioDecryptor *AudioOpen(const wchar_t *path, KeyDbCache *keydb_cache,
                          const wchar_t *keydb_setting,
                          wchar_t *err, size_t errcap);
uint64_t AudioSize(const AudioDecryptor *d);
uint64_t AudioOffset(const AudioDecryptor *d);
uint32_t AudioVersion(const AudioDecryptor *d);
bool AudioReadDecrypted(AudioDecryptor *d, uint64_t offset,
                        uint8_t *buf, size_t len,
                        wchar_t *err, size_t errcap);
void AudioClose(AudioDecryptor *d);

const wchar_t *SniffAudioExt(const uint8_t *buf, size_t len, bool *recognized);

#endif
