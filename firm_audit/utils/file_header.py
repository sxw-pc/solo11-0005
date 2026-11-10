"""纯 Python 文件魔数与后缀双识别，libmagic 缺失时自动降级。"""

from __future__ import annotations

import codecs
from pathlib import Path

_MAGIC = (
    (b"\x7fELF", "application/x-elf", "executable"),
    (b"MZ", "application/x-dosexec", "executable"),
    (b"\xca\xfe\xba\xbe", "application/x-mach-binary", "executable"),
    (b"\x89PNG\r\n\x1a\n", "image/png", "image"),
    (b"\xff\xd8\xff", "image/jpeg", "image"),
    (b"GIF87a", "image/gif", "image"),
    (b"GIF89a", "image/gif", "image"),
    (b"BM", "image/bmp", "image"),
    (b"%PDF-", "application/pdf", "document"),
    (b"PK\x03\x04", "application/zip", "archive"),
    (b"PK\x05\x06", "application/zip", "archive"),
    (b"\x1f\x8b", "application/gzip", "archive"),
    (b"BZh", "application/x-bzip2", "archive"),
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed", "archive"),
    (b"Rar!\x1a\x07", "application/vnd.rar", "archive"),
    (b"SQLite format 3\x00", "application/vnd.sqlite3", "database"),
    (b"\x00asm", "application/wasm", "executable"),
)
_SUFFIX_KINDS = {
    "image": {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".bmp",
        ".webp",
        ".ico",
        ".tif",
        ".tiff",
    },
    "audio": {".mp3", ".wav", ".ogg", ".flac", ".aac", ".m4a"},
    "video": {".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm"},
    "archive": {
        ".zip",
        ".gz",
        ".tgz",
        ".bz2",
        ".xz",
        ".7z",
        ".rar",
        ".tar",
        ".jar",
        ".apk",
        ".ipk",
    },
    "text": {
        ".txt",
        ".conf",
        ".cfg",
        ".ini",
        ".sh",
        ".php",
        ".html",
        ".htm",
        ".js",
        ".css",
        ".sql",
        ".xml",
        ".json",
        ".yaml",
        ".yml",
        ".pem",
        ".crt",
        ".key",
        ".log",
        ".md",
        ".csv",
        ".service",
        ".rules",
    },
}


def is_probably_binary(head: bytes) -> bool:
    """根据 NUL 与控制字符比例判断二进制。"""
    if not head:
        return False
    if head.startswith((b"\x7fELF", b"MZ")):
        return True
    control = sum(1 for byte in head if byte < 32 and byte not in (9, 10, 13))
    if b"\x00" in head:
        return True
    return control / len(head) > 0.20


def magic_from_head(head: bytes) -> tuple[str, str] | None:
    """返回 (MIME, kind)；tar 魔数位于偏移 257。"""
    for magic, mime, kind in _MAGIC:
        if head.startswith(magic):
            return mime, kind
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "application/x-tar", "archive"
    return None


def suffix_kind(name: str) -> tuple[str, str] | None:
    suffix = Path(name).suffix.lower()
    for kind, suffixes in _SUFFIX_KINDS.items():
        if suffix in suffixes:
            mime = {
                "image": "image/unknown",
                "audio": "audio/unknown",
                "video": "video/unknown",
                "archive": "application/octet-stream",
                "text": "text/plain",
            }[kind]
            return mime, kind
    return None


def detect_file_type(name: str, head: bytes) -> dict:
    """魔数优先、后缀补充，返回统一类型信息。"""
    if head.startswith(
        (
            codecs.BOM_UTF16_LE,
            codecs.BOM_UTF16_BE,
            codecs.BOM_UTF32_LE,
            codecs.BOM_UTF32_BE,
        )
    ):
        return {
            "mime": "text/plain",
            "kind": "text",
            "is_binary": False,
            "source": "bom",
        }
    by_magic = magic_from_head(head)
    by_suffix = suffix_kind(name)
    if by_magic:
        mime, kind = by_magic
        source = "magic"
        is_binary = kind != "text"
    elif by_suffix:
        mime, kind = by_suffix
        source = "suffix"
        is_binary = kind != "text"
    else:
        mime, kind, source = "application/octet-stream", "unknown", "content"
        is_binary = is_probably_binary(head)
    binary = is_binary if by_magic or by_suffix else is_probably_binary(head)
    if not binary and kind == "unknown":
        kind = "text"
        mime = "text/plain"
    return {"mime": mime, "kind": kind, "is_binary": binary, "source": source}


def read_head(path: str | Path, size: int = 4096) -> bytes:
    try:
        with Path(path).open("rb") as handle:
            return handle.read(size)
    except OSError:
        return b""
