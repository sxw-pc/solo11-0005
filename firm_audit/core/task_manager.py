"""扫描任务生命周期管理：异步执行、进度回调与最近任务持久化。"""

from __future__ import annotations

import json
import os
import re
import threading
import uuid
from pathlib import Path

from firm_audit.core.path_validator import validate_directory, validate_target
from firm_audit.core.scanner import Scanner
from firm_audit.core.storage import (
    cleanup_data,
    data_home,
    history_file,
    reports_root,
)
from firm_audit.models.task import ScanOptions, ScanTask, now_iso
from firm_audit.report import report_filename, write_reports

MAX_HISTORY = 10
TASK_ID_RE = re.compile(r"^[A-Za-z0-9_-]{6,64}$")
ALLOWED_FORMATS = {"json", "md", "html"}


class TaskBusyError(RuntimeError):
    """已有扫描任务运行中。"""


class TaskManager:
    def __init__(self, home: Path | None = None) -> None:
        self.home = home or data_home()
        self.report_root = reports_root(self.home)
        self._tasks: dict[str, ScanTask] = {}
        self._lock = threading.RLock()
        self._active: str | None = None
        self._history = self._load_history()

    def submit(self, options: ScanOptions) -> ScanTask:
        validate_target(options.target)
        if options.rules_dir:
            validate_directory(options.rules_dir, "自定义规则目录")
        with self._lock:
            if self._active:
                raise TaskBusyError("已有扫描任务正在执行，请稍后重试")
            task_id = uuid.uuid4().hex[:12]
            task = ScanTask(task_id=task_id, options=options)
            self._tasks[task_id] = task
            self._active = task_id
        thread = threading.Thread(
            target=self._run,
            args=(task,),
            name=f"firm-audit-{task_id}",
            daemon=True,
        )
        thread.start()
        return task

    def _run(self, task: ScanTask) -> None:
        try:
            with self._lock:
                task.status = "running"
                task.started_at = now_iso()
                task.phase = "正在加载规则"
            scanner = Scanner(
                task.options,
                task.task_id,
                progress=lambda data: self._on_progress(task, data),
            )
            result = scanner.scan()
            target_dir = self.report_root / task.task_id
            paths = write_reports(result, target_dir, task.options.formats)
            with self._lock:
                task.result = result
                task.reports = {fmt: path.name for fmt, path in paths.items()}
                task.findings_count = len(result.findings)
                task.files_total = result.files_total
                task.files_processed = result.files_scanned
                task.stats = {
                    "duration_seconds": result.duration_seconds,
                    "risk_counts": result.risk_counts,
                    "rules_loaded": result.rules_loaded,
                    "rule_version": result.rule_version,
                    "report_dir": str(target_dir),
                }
                task.warnings = result.warnings
                task.status = "completed"
                task.phase = "扫描完成"
                task.progress = 100
                task.current_file = ""
                task.finished_at = now_iso()
                self._active = None
                self._record_history(task)
        except Exception as exc:  # 后台线程必须保留任务失败现场
            with self._lock:
                task.status = "failed"
                task.phase = "扫描失败"
                task.error = str(exc)
                task.finished_at = now_iso()
                task.progress = 0
                self._active = None
                self._record_history(task)

    def _on_progress(self, task: ScanTask, data: dict) -> None:
        with self._lock:
            task.phase = data.get("phase", task.phase)
            task.progress = int(data.get("progress", task.progress))
            task.files_total = int(data.get("files_total", task.files_total))
            task.files_processed = int(
                data.get("files_processed", task.files_processed)
            )
            task.findings_count = int(data.get("findings_count", task.findings_count))
            task.current_file = data.get("current_file", "")

    def get(self, task_id: str) -> ScanTask | None:
        if not TASK_ID_RE.match(task_id or ""):
            return None
        with self._lock:
            return self._tasks.get(task_id)

    def list_tasks(self) -> list[dict]:
        with self._lock:
            active = [
                task.public()
                for task in self._tasks.values()
                if task.status in {"pending", "running"}
            ]
        combined = active + self._history
        combined.sort(key=lambda item: item.get("created_at", ""), reverse=True)
        return combined[:MAX_HISTORY]

    def report_path(self, task_id: str, report_format: str) -> Path | None:
        if not TASK_ID_RE.match(task_id or "") or report_format not in ALLOWED_FORMATS:
            return None
        directory = (self.report_root / task_id).resolve()
        try:
            directory.relative_to(self.report_root.resolve())
        except ValueError:
            return None
        name = report_filename(task_id, report_format)
        path = directory / name
        return path if path.is_file() else None

    def load_report(self, task_id: str, report_format: str = "json") -> dict | None:
        path = self.report_path(task_id, report_format)
        if path is None or report_format != "json":
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def _load_history(self) -> list[dict]:
        path = history_file(self.home)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        if not isinstance(data, list):
            return []
        return [item for item in data if isinstance(item, dict)][:MAX_HISTORY]

    def _record_history(self, task: ScanTask) -> None:
        directory = self.report_root / task.task_id
        entry = task.public()
        entry["report_dir"] = str(directory)
        entry["report_paths"] = {
            fmt: str(directory / name) for fmt, name in task.reports.items()
        }
        self._history = [
            item for item in self._history if item.get("task_id") != task.task_id
        ]
        self._history.insert(0, entry)
        self._history = self._history[:MAX_HISTORY]
        self._save_history()

    def _save_history(self) -> None:
        path = history_file(self.home)
        temporary = path.with_suffix(".tmp")
        payload = json.dumps(self._history, ensure_ascii=False, indent=2)
        temporary.write_text(payload, encoding="utf-8")
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        temporary.replace(path)

    def cleanup(self) -> bool:
        with self._lock:
            if self._active:
                raise TaskBusyError("扫描运行中，无法清理数据目录")
            removed = cleanup_data(self.home)
            self._tasks.clear()
            self._history = []
            return removed
