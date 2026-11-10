"""文件哈希与结果去重工具。"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Iterable, TypeVar

T = TypeVar("T")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    """流式计算文件 SHA-256，不将整个文件读入内存。"""
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def dedupe(items: Iterable[T], key) -> list[T]:
    """按 key 保留首次出现项。"""
    seen: set = set()
    result: list[T] = []
    for item in items:
        marker = key(item)
        if marker in seen:
            continue
        seen.add(marker)
        result.append(item)
    return result
