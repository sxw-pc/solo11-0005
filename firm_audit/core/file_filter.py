"""文件遍历、大小阈值、类型过滤与只读内容加载。"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from firm_audit.utils.encoding_util import decode_bytes
from firm_audit.utils.file_header import detect_file_type, read_head
from firm_audit.utils.hash_util import sha256_file
from firm_audit.utils.string_extractor import extract_file_strings

SKIPPED_KINDS = {"image", "audio", "video", "archive"}
MAX_STRING_FILES = 2_000_000


@dataclass(frozen=True)
class FileCandidate:
    path: Path
    rel_path: str
    size: int
    depth: int
    kind_hint: str = ""


@dataclass
class ScanFile:
    """单个待检测文件的内存快照，扫描结束后释放。"""

    path: Path
    rel_path: str
    size: int
    mode: int
    mime: str
    kind: str
    is_binary: bool
    sha256: str
    text: str = ""
    lines: tuple[str, ...] = ()
    strings: tuple = ()
    encoding: str = ""

    @property
    def is_world_writable(self) -> bool:
        return bool(self.mode & stat.S_IWOTH)

    @property
    def is_world_readable(self) -> bool:
        return bool(self.mode & stat.S_IROTH)


class FileFilter:
    """按深度、大小、类型收集目标文件，符号链接一律跳过。"""

    def __init__(
        self,
        root: Path,
        max_size_bytes: int,
        max_depth: int,
        extract_archives: bool = False,
    ) -> None:
        self.root = root
        self.max_size_bytes = max_size_bytes
        self.max_depth = max_depth
        self.extract_archives = extract_archives
        self.skipped = {
            "symlink": 0,
            "large": 0,
            "type": 0,
            "depth": 0,
            "error": 0,
        }
        self.total_bytes = 0
        self.archives: list[FileCandidate] = []
        self.warnings: list[str] = []

    def collect(self) -> list[FileCandidate]:
        if self.root.is_file():
            candidate = self._candidate(self.root, self.root.name, 0)
            return [candidate] if candidate else []
        found: list[FileCandidate] = []
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            current = Path(dirpath)
            depth = len(current.relative_to(self.root).parts)
            dirnames[:] = sorted(
                name
                for name in dirnames
                if not (current / name).is_symlink() and depth < self.max_depth
            )
            for name in sorted(filenames):
                path = current / name
                rel = path.relative_to(self.root).as_posix()
                candidate = self._candidate(path, rel, depth)
                if candidate:
                    found.append(candidate)
        return found

    def _candidate(self, path: Path, rel_path: str, depth: int) -> FileCandidate | None:
        try:
            info = path.lstat()
        except OSError:
            self.skipped["error"] += 1
            return None
        if stat.S_ISLNK(info.st_mode):
            self.skipped["symlink"] += 1
            return None
        if not stat.S_ISREG(info.st_mode):
            return None
        if depth > self.max_depth:
            self.skipped["depth"] += 1
            return None
        self.total_bytes += info.st_size
        if info.st_size > self.max_size_bytes:
            self.skipped["large"] += 1
            return None
        kind_hint = detect_file_type(path.name, read_head(path, 512))["kind"]
        is_archive = kind_hint == "archive" or path.suffix.lower() in {
            ".zip",
            ".gz",
            ".tgz",
            ".bz2",
            ".xz",
            ".7z",
            ".rar",
            ".tar",
        }
        if is_archive:
            if self.extract_archives:
                self.archives.append(
                    FileCandidate(path, rel_path, info.st_size, depth, "archive")
                )
            else:
                self.skipped["type"] += 1
            return None
        if kind_hint in SKIPPED_KINDS:
            self.skipped["type"] += 1
            return None
        return FileCandidate(path, rel_path, info.st_size, depth, kind_hint)

    def load(self, candidate: FileCandidate) -> ScanFile | None:
        """读取文件并构建内存快照，文件名与魔数双校验。"""
        try:
            head = read_head(candidate.path)
            file_type = detect_file_type(candidate.path.name, head)
            if file_type["kind"] in SKIPPED_KINDS:
                self.skipped["type"] += 1
                return None
            info = candidate.path.stat()
            digest = sha256_file(candidate.path)
            if file_type["is_binary"]:
                strings = tuple(extract_file_strings(candidate.path))
                return ScanFile(
                    path=candidate.path,
                    rel_path=candidate.rel_path,
                    size=info.st_size,
                    mode=info.st_mode,
                    mime=file_type["mime"],
                    kind=file_type["kind"],
                    is_binary=True,
                    sha256=digest,
                    strings=strings[:MAX_STRING_FILES],
                )
            data = candidate.path.read_bytes()
            text, encoding = decode_bytes(data)
            return ScanFile(
                path=candidate.path,
                rel_path=candidate.rel_path,
                size=info.st_size,
                mode=info.st_mode,
                mime=file_type["mime"],
                kind=file_type["kind"],
                is_binary=False,
                sha256=digest,
                text=text,
                lines=tuple(text.splitlines()),
                encoding=encoding,
            )
        except (OSError, ValueError, MemoryError) as exc:
            self.warnings.append(f"读取失败 {candidate.rel_path}: {exc}")
            self.skipped["error"] += 1
            return None


def survey(root: Path, max_depth: int) -> dict:
    """扫描前快速统计，供大目录确认提示使用。"""
    files = 0
    total = 0
    if root.is_file():
        return {"files": 1, "bytes": root.stat().st_size}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        depth = len(current.relative_to(root).parts)
        dirnames[:] = [
            name
            for name in dirnames
            if not (current / name).is_symlink() and depth < max_depth
        ]
        for name in filenames:
            path = current / name
            try:
                info = path.lstat()
            except OSError:
                continue
            if stat.S_ISREG(info.st_mode) and not path.is_symlink():
                files += 1
                total += info.st_size
    return {"files": files, "bytes": total}
