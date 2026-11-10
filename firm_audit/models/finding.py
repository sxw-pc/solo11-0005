"""检测结果与证据数据模型。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .rule import RiskLevel

CATEGORY_LABELS = {
    "hardcode_cred": "硬编码凭证",
    "sensitive_file": "敏感文件",
    "insecure_config": "不安全配置",
    "debug_interface": "遗留调试接口",
}


@dataclass
class Evidence:
    """命中证据，line 与 offset 为 0 表示文件级证据。"""

    snippet: str
    line: int = 0
    offset: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"line": self.line, "offset": self.offset, "snippet": self.snippet}


@dataclass
class Finding:
    """单条漏洞检测结果。"""

    rule_id: str
    title: str
    category: str
    severity: RiskLevel
    file_path: str
    evidence: Evidence
    description: str
    remediation: str
    scene: str = ""
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> tuple[str, str]:
        """同一文件同一规则只保留一条结果。"""
        return self.rule_id, self.file_path

    @property
    def category_label(self) -> str:
        return CATEGORY_LABELS.get(self.category, self.category)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "category": self.category,
            "category_label": self.category_label,
            "severity": self.severity.value,
            "severity_label": self.severity.label,
            "file": self.file_path,
            "scene": self.scene,
            "evidence": self.evidence.to_dict(),
            "description": self.description,
            "remediation": self.remediation,
            "tags": list(self.tags),
            "metadata": dict(self.metadata),
        }


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """按风险等级、文件路径、规则 ID 稳定排序。"""
    return sorted(
        findings,
        key=lambda item: (
            -item.severity.weight,
            item.file_path,
            item.rule_id,
            item.evidence.line,
            item.evidence.offset,
        ),
    )


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    return {
        level.value: sum(f.severity is level for f in findings)
        for level in (RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW)
    }
