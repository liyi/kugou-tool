#include "app.h"
#include "util.h"

FileKind KindFromPath(const wchar_t *path)
{
    if (!path) return KIND_UNKNOWN;
    if (ExtEquals(path, L".krc")) return KIND_KRC;
    if (ExtEquals(path, L".kgg")) return KIND_KGG;
    if (ExtEquals(path, L".kgma")) return KIND_KGMA;
    if (ExtEquals(path, L".kgm")) return KIND_KGM;
    if (ExtEquals(path, L".vpr")) return KIND_VPR;
    return KIND_UNKNOWN;
}

const wchar_t *KindDisplayName(FileKind kind)
{
    switch (kind) {
    case KIND_KRC: return L"KRC";
    case KIND_KGG: return L"KGG";
    case KIND_KGMA: return L"KGMA";
    case KIND_KGM: return L"KGM";
    case KIND_VPR: return L"VPR";
    default: return L"未知";
    }
}

bool KindHasSupportedExt(const wchar_t *path)
{
    return KindFromPath(path) != KIND_UNKNOWN;
}

bool IsSupportedAudioKind(FileKind kind)
{
    return kind == KIND_KGG || kind == KIND_KGMA || kind == KIND_KGM || kind == KIND_VPR;
}
