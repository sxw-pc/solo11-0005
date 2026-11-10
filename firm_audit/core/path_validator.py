"""扫描路径合法性校验、系统目录黑名单与目录遍历防护。"""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath

POSIX_FORBIDDEN = {
    "/",
    "/etc",
    "/usr",
    "/bin",
    "/sbin",
    "/boot",
    "/dev",
    "/proc",
    "/sys",
    "/lib",
    "/lib64",
}


class PathValidationError(ValueError):
    """路径不安全或不可用。"""


def _windows_forbidden() -> set[str]:
    if os.name != "nt":
        return set()
    values: set[str] = set()
    for key in ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData"):
        value = os.environ.get(key)
        if value:
            values.add(os.path.normcase(os.path.abspath(value)))
    return values


def _reject_dotdot(raw: str) -> None:
    normalized = raw.replace("\\", "/")
    if ".." in PurePosixPath(normalized).parts:
        raise PathValidationError("路径中禁止包含 '..' 目录跳转")


def _hit_posix_forbidden(candidate: PurePosixPath) -> str | None:
    for forbidden in POSIX_FORBIDDEN:
        target = PurePosixPath(forbidden)
        if forbidden != "/" and (candidate == target or target in candidate.parents):
            return forbidden
    return None


def _check_windows_blacklist(resolved: Path) -> None:
    candidate = os.path.normcase(str(resolved))
    for forbidden in _windows_forbidden():
        if candidate == forbidden or candidate.startswith(
            forbidden.rstrip("\\") + "\\"
        ):
            raise PathValidationError("禁止扫描 Windows 系统关键目录")


def _check_blacklist(path: Path, raw: str) -> None:
    resolved = path.resolve()
    if resolved == Path(resolved.anchor):
        raise PathValidationError("禁止扫描文件系统根目录")
    if os.name == "nt":
        _check_windows_blacklist(resolved)
        return
    candidates = (
        PurePosixPath(raw.replace("\\", "/")),
        PurePosixPath(resolved.as_posix()),
    )
    for candidate in candidates:
        hit = _hit_posix_forbidden(candidate)
        if hit:
            raise PathValidationError(f"禁止扫描系统关键目录: {hit}")


def _check_symlink(raw_path: Path) -> None:
    try:
        if raw_path.is_symlink():
            raise PathValidationError("目标路径为符号链接，已拦截")
    except OSError as exc:
        raise PathValidationError(f"无法检查路径: {exc}") from exc


def validate_target(raw: str, must_exist: bool = True) -> Path:
    """规范化并校验扫描目标，返回绝对 Path。"""
    if not isinstance(raw, str) or not raw.strip():
        raise PathValidationError("扫描路径不能为空")
    if "\x00" in raw:
        raise PathValidationError("扫描路径包含非法字符")
    _reject_dotdot(raw)
    raw_path = Path(raw).expanduser()
    if must_exist and not raw_path.exists():
        raise PathValidationError("扫描路径不存在")
    _check_symlink(raw_path)
    try:
        resolved = raw_path.resolve(strict=must_exist)
    except (OSError, RuntimeError) as exc:
        raise PathValidationError(f"路径解析失败: {exc}") from exc
    _check_blacklist(resolved, raw)
    return resolved


def validate_directory(raw: str, label: str = "目录") -> Path:
    path = validate_target(raw)
    if not path.is_dir():
        raise PathValidationError(f"{label}不是有效目录")
    return path


def ensure_within(root: Path, candidate: Path) -> Path:
    """确保 candidate 位于 root 下，防止符号链接逃逸。"""
    root_resolved = root.resolve()
    candidate_resolved = candidate.resolve()
    try:
        common = Path(os.path.commonpath((str(root_resolved), str(candidate_resolved))))
    except ValueError as exc:
        raise PathValidationError("路径跨越不同磁盘，已拦截") from exc
    if common != root_resolved:
        raise PathValidationError("路径越界，已拦截")
    return candidate_resolved


def safe_join(root: Path, relative: str) -> Path:
    """安全拼接相对路径，拒绝绝对路径与 .. 跳转。"""
    if not relative or "\x00" in relative:
        raise PathValidationError("相对路径不能为空")
    posix = PurePosixPath(relative.replace("\\", "/"))
    if posix.is_absolute() or ".." in posix.parts:
        raise PathValidationError("检测到目录遍历路径")
    return ensure_within(root, root.joinpath(*posix.parts))


def is_within(root: Path, candidate: Path) -> bool:
    try:
        ensure_within(root, candidate)
        return True
    except (PathValidationError, OSError):
        return False
