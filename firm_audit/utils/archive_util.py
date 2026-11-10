"""压缩包安全解包，防止 Zip Slip 与解压炸弹。"""

from __future__ import annotations

import shutil
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO

MAX_UNCOMPRESSED = 256 * 1024 * 1024
MAX_MEMBERS = 5000


class ArchiveExtractionError(ValueError):
    """压缩包不安全或无法解包。"""


def _safe_member(name: str) -> PurePosixPath:
    path = PurePosixPath(name.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ArchiveExtractionError(f"压缩包成员路径越界: {name}")
    return path


def _copy_limited(source: BinaryIO, target: Path, remaining: int) -> int:
    target.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with target.open("wb") as handle:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            written += len(chunk)
            if written > remaining:
                raise ArchiveExtractionError("压缩包解压后体积超过安全阈值")
            handle.write(chunk)
    return written


def _extract_zip(archive: Path, destination: Path) -> None:
    with zipfile.ZipFile(archive) as bundle:
        members = bundle.infolist()
        if len(members) > MAX_MEMBERS:
            raise ArchiveExtractionError("压缩包成员数量超过安全阈值")
        budget = MAX_UNCOMPRESSED
        declared = sum(item.file_size for item in members)
        if declared > MAX_UNCOMPRESSED:
            raise ArchiveExtractionError("压缩包解压后体积超过安全阈值")
        for item in members:
            relative = _safe_member(item.filename)
            target = destination.joinpath(*relative.parts)
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if ((item.external_attr >> 16) & 0o170000) == 0o120000:
                raise ArchiveExtractionError("压缩包包含符号链接，已拒绝")
            with bundle.open(item) as source:
                budget -= _copy_limited(source, target, budget)


def _extract_tar(archive: Path, destination: Path) -> None:
    with tarfile.open(archive, "r:*") as bundle:
        members = bundle.getmembers()
        if len(members) > MAX_MEMBERS:
            raise ArchiveExtractionError("压缩包成员数量超过安全阈值")
        if sum(item.size for item in members) > MAX_UNCOMPRESSED:
            raise ArchiveExtractionError("压缩包解压后体积超过安全阈值")
        budget = MAX_UNCOMPRESSED
        for item in members:
            if item.issym() or item.islnk() or item.isdev():
                raise ArchiveExtractionError("压缩包包含链接或设备文件，已拒绝")
            relative = _safe_member(item.name)
            target = destination.joinpath(*relative.parts)
            if item.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not item.isfile():
                continue
            source = bundle.extractfile(item)
            if source is None:
                continue
            with source:
                budget -= _copy_limited(source, target, budget)


def safe_extract(archive: Path, destination: Path) -> None:
    """仅解包到调用方指定的空临时目录。"""
    destination.mkdir(parents=True, exist_ok=True)
    if zipfile.is_zipfile(archive):
        _extract_zip(archive, destination)
    elif tarfile.is_tarfile(archive):
        _extract_tar(archive, destination)
    else:
        raise ArchiveExtractionError("不支持的压缩包格式")


def cleanup_directory(path: Path) -> None:
    """扫描结束后删除临时解包目录。"""
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)
