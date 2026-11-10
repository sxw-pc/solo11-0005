"""用户目录隐藏数据目录管理，支持一键清理。"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

APP_DIR_NAME = ".firm_audit"


def data_home() -> Path:
    """所有任务数据固定存放在用户目录隐藏文件夹。"""
    override = os.environ.get("FIRM_AUDIT_HOME")
    path = Path(override).expanduser() if override else Path.home() / APP_DIR_NAME
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path.resolve()


def reports_root(home: Path | None = None) -> Path:
    path = (home or data_home()) / "reports"
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path


def temp_root(home: Path | None = None) -> Path:
    path = (home or data_home()) / "tmp"
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path


def create_temp_dir(prefix: str = "firm_audit_") -> Path:
    return Path(tempfile.mkdtemp(prefix=prefix, dir=temp_root()))


def cleanup_data(home: Path | None = None) -> bool:
    """仅在隐藏数据目录语义下清理，拒绝用户主目录或根目录。"""
    target = (home or data_home()).resolve()
    if target == Path(target.anchor) or target == Path.home().resolve():
        raise ValueError("拒绝清理主目录或文件系统根目录")
    if target.name != APP_DIR_NAME and not os.environ.get("FIRM_AUDIT_HOME"):
        raise ValueError("数据目录名称异常，拒绝清理")
    if target.exists():
        shutil.rmtree(target)
        return True
    return False


def history_file(home: Path | None = None) -> Path:
    return (home or data_home()) / "tasks.json"
