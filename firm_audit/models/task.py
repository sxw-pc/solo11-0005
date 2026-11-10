"""扫描任务与参数数据模型。"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

ALLOWED_FORMATS = ("json", "md", "html")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class ScanOptions:
    """一次扫描的参数，路径由调用方完成安全校验。"""

    target: str
    rules_dir: str | None = None
    max_size_mb: int = 100
    max_depth: int = 15
    formats: tuple[str, ...] = ALLOWED_FORMATS
    output_dir: str | None = None
    extract_archives: bool = False

    def __post_init__(self) -> None:
        self.formats = tuple(dict.fromkeys(str(item).lower() for item in self.formats))
        invalid = [item for item in self.formats if item not in ALLOWED_FORMATS]
        if invalid:
            raise ValueError(f"不支持的报告格式: {', '.join(invalid)}")
        if not 1 <= int(self.max_size_mb) <= 2048:
            raise ValueError("max_size_mb 必须在 1-2048 之间")
        if not 1 <= int(self.max_depth) <= 64:
            raise ValueError("max_depth 必须在 1-64 之间")

    @property
    def max_size_bytes(self) -> int:
        return int(self.max_size_mb) * 1024 * 1024

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "rules_dir": self.rules_dir,
            "max_size_mb": self.max_size_mb,
            "max_depth": self.max_depth,
            "formats": list(self.formats),
            "extract_archives": self.extract_archives,
        }

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> "ScanOptions":
        formats = data.get("formats", ALLOWED_FORMATS)
        if isinstance(formats, str):
            formats = [part for part in formats.split(",") if part.strip()]
        if not isinstance(formats, Iterable):
            raise ValueError("formats 必须为列表")
        return cls(
            target=str(data.get("target", "")).strip(),
            rules_dir=(
                str(data["rules_dir"]).strip() if data.get("rules_dir") else None
            ),
            max_size_mb=int(data.get("max_size_mb", 100)),
            max_depth=int(data.get("max_depth", 15)),
            formats=tuple(formats),
            output_dir=(
                str(data["output_dir"]).strip() if data.get("output_dir") else None
            ),
            extract_archives=bool(data.get("extract_archives", False)),
        )


@dataclass
class ScanTask:
    """任务运行时状态；result 不写入持久化元数据。"""

    task_id: str
    options: ScanOptions
    status: str = "pending"
    created_at: str = field(default_factory=now_iso)
    started_at: str | None = None
    finished_at: str | None = None
    progress: int = 0
    phase: str = "等待执行"
    files_total: int = 0
    files_processed: int = 0
    findings_count: int = 0
    current_file: str = ""
    error: str = ""
    reports: dict[str, str] = field(default_factory=dict)
    stats: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    result: Any = field(default=None, repr=False)

    def public(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "progress": self.progress,
            "phase": self.phase,
            "files_total": self.files_total,
            "files_processed": self.files_processed,
            "findings_count": self.findings_count,
            "current_file": self.current_file,
            "error": self.error,
            "reports": dict(self.reports),
            "stats": dict(self.stats),
            "warnings": list(self.warnings),
            "options": self.options.to_dict(),
        }
