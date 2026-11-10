"""二进制可打印字符串提取。"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16LE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
UTF16BE_RE = re.compile(rb"(?:\x00[\x20-\x7e]){4,}")


@dataclass(frozen=True)
class ExtractedString:
    offset: int
    value: str
    encoding: str = "ascii"


def extract_strings(data: bytes, min_length: int = 4) -> list[ExtractedString]:
    """提取 ASCII、UTF-16LE/BE 字符串并按偏移排序。"""
    if not data:
        return []
    ascii_pattern = re.compile(rb"[\x20-\x7e]{%d,}" % max(1, min_length))
    le_pattern = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % max(1, min_length))
    be_pattern = re.compile(rb"(?:\x00[\x20-\x7e]){%d,}" % max(1, min_length))
    found: list[ExtractedString] = []
    for match in ascii_pattern.finditer(data):
        found.append(
            ExtractedString(match.start(), match.group().decode("ascii"), "ascii")
        )
    for match in le_pattern.finditer(data):
        value = match.group().decode("utf-16-le", errors="replace")
        found.append(ExtractedString(match.start(), value, "utf-16-le"))
    for match in be_pattern.finditer(data):
        value = match.group().decode("utf-16-be", errors="replace")
        found.append(ExtractedString(match.start(), value, "utf-16-be"))
    return sorted(found, key=lambda item: (item.offset, item.encoding))


def extract_file_strings(
    path: str | Path, min_length: int = 4
) -> list[ExtractedString]:
    """只读提取，原始文件不做任何修改。"""
    return extract_strings(Path(path).read_bytes(), min_length=min_length)
