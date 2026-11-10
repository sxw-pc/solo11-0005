"""隐藏数据目录与清理安全测试。"""

from pathlib import Path

import pytest

from firm_audit.core.storage import (
    APP_DIR_NAME, cleanup_data, create_temp_dir, data_home, history_file,
    reports_root, temp_root,
)


def test_data_home_override_and_cleanup(tmp_path, monkeypatch):
    monkeypatch.setenv("FIRM_AUDIT_HOME", str(tmp_path / "home"))
    home = data_home()
    assert home.name == "home" and home.is_dir()
    assert reports_root().is_dir() and temp_root().is_dir()
    assert history_file() == home / "tasks.json"
    created = create_temp_dir()
    assert created.parent == temp_root() and created.is_dir()
    assert reports_root(home).parent == home
    monkeypatch.delenv("FIRM_AUDIT_HOME", raising=False)
    for bad in (Path.home(), Path(Path.cwd().anchor), tmp_path):
        with pytest.raises(ValueError):
            cleanup_data(bad)
    target = tmp_path / APP_DIR_NAME
    target.mkdir()
    (target / "tasks.json").write_text("[]", encoding="utf-8")
    assert cleanup_data(target) is True and not target.exists()
    assert cleanup_data(target) is False
    monkeypatch.setenv("FIRM_AUDIT_HOME", str(tmp_path / "custom"))
    custom = data_home()
    assert cleanup_data() is True and not custom.exists()
