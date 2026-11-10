"""静态度量扫描编排：文件预处理、检测器调度与统计。"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from firm_audit.core.file_filter import FileCandidate, FileFilter
from firm_audit.core.path_validator import validate_directory, validate_target
from firm_audit.core.rule_engine import RuleEngine
from firm_audit.core.storage import create_temp_dir
from firm_audit.detectors import build_detectors
from firm_audit.models.finding import Finding, severity_counts, sort_findings
from firm_audit.models.task import ScanOptions
from firm_audit.utils.archive_util import (
    ArchiveExtractionError,
    cleanup_directory,
    safe_extract,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class ScanResult:
    task_id: str
    target: str
    options: ScanOptions
    started_at: str
    finished_at: str
    duration_seconds: float
    files_total: int
    files_scanned: int
    files_skipped: int
    total_bytes: int
    scanned_bytes: int
    rules_loaded: int
    rule_version: str
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    skipped: dict[str, int] = field(default_factory=dict)

    @property
    def risk_counts(self) -> dict[str, int]:
        return severity_counts(self.findings)

    @property
    def category_counts(self) -> dict[str, int]:
        result: dict[str, int] = {}
        for finding in self.findings:
            result[finding.category] = result.get(finding.category, 0) + 1
        return result


class Scanner:
    def __init__(
        self,
        options: ScanOptions,
        task_id: str | None = None,
        progress: Callable[[dict], None] | None = None,
    ) -> None:
        self.options = options
        self.task_id = task_id or uuid.uuid4().hex[:12]
        self.progress = progress
        self.warnings: list[str] = []
        self.skipped = {"symlink": 0, "large": 0, "type": 0, "depth": 0, "error": 0}
        self.files_total = 0
        self.files_processed = 0
        self.findings_count = 0
        self.total_bytes = 0
        self.scanned_bytes = 0

    def scan(self) -> ScanResult:
        started = time.monotonic()
        started_at = _now()
        target = validate_target(self.options.target)
        rules_dir = None
        if self.options.rules_dir:
            rules_dir = validate_directory(self.options.rules_dir, "自定义规则目录")
        engine = RuleEngine.from_directories(custom=rules_dir)
        self.warnings.extend(engine.warnings)
        detectors = build_detectors(engine)
        file_filter = FileFilter(
            target,
            self.options.max_size_bytes,
            self.options.max_depth,
            self.options.extract_archives,
        )
        candidates = file_filter.collect()
        self._merge_filter_stats(file_filter)
        self.files_total = len(candidates)
        self._emit("扫描文件中", "")
        findings = self._scan_candidates(candidates, file_filter, detectors, "")
        if self.options.extract_archives and file_filter.archives:
            findings.extend(self._scan_archives(file_filter.archives, detectors))
        self.warnings.extend(file_filter.warnings)
        unique = self._dedupe(findings)
        self._emit("扫描完成", "")
        return ScanResult(
            task_id=self.task_id,
            target=str(target),
            options=self.options,
            started_at=started_at,
            finished_at=_now(),
            duration_seconds=round(time.monotonic() - started, 3),
            files_total=self.files_total,
            files_scanned=self.files_processed,
            files_skipped=sum(self.skipped.values()),
            total_bytes=self.total_bytes,
            scanned_bytes=self.scanned_bytes,
            rules_loaded=len(engine.rules),
            rule_version=engine.version,
            findings=sort_findings(unique),
            warnings=list(self.warnings),
            skipped=dict(self.skipped),
        )

    def _scan_candidates(
        self,
        candidates: list[FileCandidate],
        file_filter: FileFilter,
        detectors,
        prefix: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for candidate in candidates:
            display = prefix + candidate.rel_path
            try:
                scan_file = file_filter.load(candidate)
            except Exception as exc:  # 单文件异常不终止全量扫描
                self.warnings.append(f"处理失败 {display}: {exc}")
                self.skipped["error"] += 1
                scan_file = None
            if scan_file is not None:
                scan_file.rel_path = display
                self.files_processed += 1
                self.scanned_bytes += scan_file.size
                file_findings: list[Finding] = []
                for detector in detectors:
                    try:
                        file_findings.extend(detector.detect(scan_file))
                    except Exception as exc:
                        self.warnings.append(f"检测器异常 {display}: {exc}")
                findings.extend(file_findings)
                self.findings_count += len(file_findings)
                self._emit("扫描文件中", display)
            else:
                self.files_processed += 1
                self._emit("扫描文件中", display)
        return findings

    def _scan_archives(self, archives: list[FileCandidate], detectors) -> list[Finding]:
        findings: list[Finding] = []
        for archive in archives:
            temp_dir = create_temp_dir()
            try:
                safe_extract(archive.path, temp_dir)
                nested = FileFilter(
                    temp_dir,
                    self.options.max_size_bytes,
                    self.options.max_depth,
                    extract_archives=False,
                )
                candidates = nested.collect()
                self._merge_filter_stats(nested)
                self.files_total += len(candidates)
                self.warnings.extend(nested.warnings)
                findings.extend(
                    self._scan_candidates(
                        candidates, nested, detectors, f"{archive.rel_path}!/"
                    )
                )
            except (ArchiveExtractionError, OSError, ValueError) as exc:
                self.warnings.append(f"解包失败 {archive.rel_path}: {exc}")
            finally:
                cleanup_directory(temp_dir)
        return findings

    def _merge_filter_stats(self, file_filter: FileFilter) -> None:
        for key, value in file_filter.skipped.items():
            self.skipped[key] = self.skipped.get(key, 0) + value
        self.total_bytes += file_filter.total_bytes

    @staticmethod
    def _dedupe(findings: list[Finding]) -> list[Finding]:
        seen: set[tuple[str, str]] = set()
        result: list[Finding] = []
        for finding in findings:
            if finding.key in seen:
                continue
            seen.add(finding.key)
            result.append(finding)
        return result

    def _emit(self, phase: str, current: str) -> None:
        if not self.progress:
            return
        total = max(self.files_total, 1)
        percent = (
            100
            if phase == "扫描完成"
            else min(99, int(self.files_processed / total * 100))
        )
        self.progress(
            {
                "phase": phase,
                "progress": percent,
                "files_total": self.files_total,
                "files_processed": self.files_processed,
                "current_file": current,
                "findings_count": self.findings_count,
            }
        )
