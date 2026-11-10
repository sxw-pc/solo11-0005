"""扫描路径安全校验测试。"""

from pathlib import Path, PurePosixPath

import pytest

from firm_audit.core import path_validator
from firm_audit.core.path_validator import (
    PathValidationError, _hit_posix_forbidden, ensure_within, is_within, safe_join,
    validate_directory, validate_target,
)


def test_reject_invalid_targets(tmp_path, monkeypatch):
    for raw in ("", "   ", "bad\x00path"):
        with pytest.raises(PathValidationError):
            validate_target(raw)
    with pytest.raises(PathValidationError, match="\\.\\."):
        validate_target(str(tmp_path / ".." / "etc"))
    with pytest.raises(PathValidationError, match="不存在"):
        validate_target(str(tmp_path / "missing"))
    monkeypatch.setattr(Path, "is_symlink", lambda self: True)
    with pytest.raises(PathValidationError, match="符号链接"):
        validate_target(str(tmp_path))


def test_validate_directory_and_roots(tmp_path):
    target = validate_target(str(tmp_path))
    assert target == tmp_path.resolve() and validate_directory(str(tmp_path)) == target
    file_path = tmp_path / "a.txt"
    file_path.write_text("x", encoding="utf-8")
    assert validate_target(str(file_path)) == file_path.resolve()
    with pytest.raises(PathValidationError, match="不是有效目录"):
        validate_directory(str(file_path))
    assert validate_target(str(tmp_path / "new"), must_exist=False).name == "new"
    with pytest.raises(PathValidationError, match="根目录"):
        validate_target(str(Path(Path.cwd().anchor)))


def test_posix_forbidden_and_windows_branch(tmp_path, monkeypatch):
    assert _hit_posix_forbidden(PurePosixPath("/etc/passwd")) == "/etc"
    assert _hit_posix_forbidden(PurePosixPath("/usr/bin")) == "/usr"
    assert _hit_posix_forbidden(PurePosixPath("/")) is None
    assert _hit_posix_forbidden(PurePosixPath("/opt/firmware")) is None
    monkeypatch.setattr(path_validator.os, "name", "nt")
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    with pytest.raises(PathValidationError, match="Windows"):
        path_validator._check_blacklist(tmp_path, str(tmp_path))
    other = tmp_path / "other"
    other.mkdir()
    monkeypatch.setenv("SystemRoot", str(tmp_path / "system"))
    path_validator._check_blacklist(other, str(other))


def test_ensure_within_and_safe_join(tmp_path):
    child = tmp_path / "a" / "b.txt"
    child.parent.mkdir()
    child.write_text("x", encoding="utf-8")
    assert ensure_within(tmp_path, child) == child.resolve()
    assert is_within(tmp_path, child) is True
    with pytest.raises(PathValidationError, match="越界"):
        ensure_within(tmp_path / "a", tmp_path)
    for bad in ("../escape", "/abs", ""):
        with pytest.raises(PathValidationError):
            safe_join(tmp_path, bad)
    assert safe_join(tmp_path, "a/b.txt") == child.resolve()
    assert is_within(tmp_path, tmp_path / "missing") is True
