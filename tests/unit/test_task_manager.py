"""异步任务管理与历史记录测试。"""

import time

import pytest

from firm_audit.core.task_manager import TaskBusyError, TaskManager
from firm_audit.models.task import ScanOptions


def wait_done(manager, task, timeout=20.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        current = manager.get(task.task_id)
        if current.status in {"completed", "failed"}:
            return current
        time.sleep(0.05)
    raise AssertionError("任务未在超时时间内完成")


def test_task_lifecycle_reports_history_and_guards(firmware_dir, tmp_path):
    manager = TaskManager(home=tmp_path / ".firm_audit")
    task = manager.submit(ScanOptions(target=str(firmware_dir), formats=("json", "md")))
    assert task.status in {"pending", "running"}
    done = wait_done(manager, task)
    assert done.status == "completed" and done.progress == 100
    assert done.findings_count == 12 and done.files_total >= 11
    assert set(done.reports) == {"json", "md"}
    assert done.stats["risk_counts"]["high"] == 11
    report = manager.report_path(task.task_id, "json")
    assert report is not None and report.is_file()
    assert manager.load_report(task.task_id)["summary"]["total"] == 12
    assert manager.load_report(task.task_id, "html") is None
    assert manager.report_path(task.task_id, "pdf") is None
    assert manager.report_path("../../etc", "json") is None
    assert manager.load_report("missingtask") is None and manager.get("bad id!") is None
    fresh = TaskManager(home=tmp_path / ".firm_audit")
    assert fresh.list_tasks()[0]["task_id"] == task.task_id
    manager._active = "running"
    with pytest.raises(TaskBusyError):
        manager.submit(ScanOptions(target=str(firmware_dir)))
    with pytest.raises(TaskBusyError):
        manager.cleanup()


def test_submit_validation_failed_cleanup_and_escape(tmp_path, firmware_dir):
    manager = TaskManager(home=tmp_path / ".firm_audit")
    for options in (ScanOptions(target=str(tmp_path / "missing")),
                    ScanOptions(target=str(firmware_dir), rules_dir=str(tmp_path / "rules"))):
        with pytest.raises(Exception):
            manager.submit(options)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "firm_audit_escape.json").write_text("{}", encoding="utf-8")
    assert manager.report_path("escape", "json") is None
    task = manager.submit(ScanOptions(target=str(tmp_path)))
    wait_done(manager, task)
    assert task.status == "completed"
    assert manager.cleanup() is True and manager.list_tasks() == []
    assert manager.cleanup() is False
