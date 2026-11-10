"""文本编码探测，兼容 UTF-8、GBK、Latin-1 与 UTF-16。"""

from __future__ import annotations

import codecs
from pathlib import Path

_BOMS = (
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF32_LE, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
)
_CANDIDATES = ("utf-8", "gb18030", "latin-1")


def _control_ratio(text: str) -> float:
    if not text:
        return 0.0
    bad = sum(1 for char in text if ord(char) < 32 and char not in "\r\n\t")
    return bad / len(text)


def _decode_bom(data: bytes) -> tuple[str, str] | None:
    for bom, name in _BOMS:
        if data.startswith(bom):
            try:
                return data.decode(name), name
            except UnicodeDecodeError:
                return None
    return None


def _decode_utf16(data: bytes) -> tuple[str, str] | None:
    if b"\x00" not in data[:4096]:
        return None
    for name in ("utf-16-le", "utf-16-be"):
        try:
            text = data.decode(name)
        except UnicodeDecodeError:
            continue
        if _control_ratio(text) < 0.05:
            return text, name
    return None


def _decode_candidate(data: bytes) -> tuple[str, str] | None:
    for name in _CANDIDATES:
        try:
            text = data.decode(name)
        except UnicodeDecodeError:
            continue
        if _control_ratio(text) < 0.10:
            return text, name
    return None


def decode_bytes(data: bytes) -> tuple[str, str]:
    """返回 (文本, 编码名)，无法确认时使用 latin-1 无损解码。"""
    if not data:
        return "", "utf-8"
    decoded = _decode_bom(data) or _decode_utf16(data) or _decode_candidate(data)
    return decoded or (data.decode("latin-1"), "latin-1")


def read_text_file(path: str | Path, max_bytes: int | None = None) -> tuple[str, str]:
    """只读方式读取并解码文本文件。"""
    data = Path(path).read_bytes()
    if max_bytes is not None:
        data = data[:max_bytes]
    return decode_bytes(data)
