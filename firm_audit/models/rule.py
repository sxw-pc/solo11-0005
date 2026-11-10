"""检测规则数据模型。"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable


class RuleValidationError(ValueError):
    """规则格式非法。"""


class RiskLevel(str, Enum):
    """风险等级，数值越大越严重。"""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @classmethod
    def parse(cls, value: Any) -> "RiskLevel":
        aliases = {
            "high": cls.HIGH,
            "高": cls.HIGH,
            "高危": cls.HIGH,
            "medium": cls.MEDIUM,
            "中": cls.MEDIUM,
            "中危": cls.MEDIUM,
            "low": cls.LOW,
            "低": cls.LOW,
            "低危": cls.LOW,
        }
        key = str(value).strip().lower()
        if key not in aliases:
            raise RuleValidationError(f"未知风险等级: {value}")
        return aliases[key]

    @property
    def label(self) -> str:
        return {self.HIGH: "高危", self.MEDIUM: "中危", self.LOW: "低危"}[self]

    @property
    def weight(self) -> int:
        return {self.HIGH: 3, self.MEDIUM: 2, self.LOW: 1}[self]


VALID_MATCH_TYPES = {"exact", "regex", "permission", "hash", "path"}
VALID_CATEGORIES = {
    "hardcode_cred",
    "sensitive_file",
    "insecure_config",
    "debug_interface",
}
RULE_ID_PATTERN = re.compile(r"^[A-Z][A-Z0-9_-]{2,63}$")


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, Iterable):
        return [str(item) for item in value if str(item).strip()]
    raise RuleValidationError("字段必须为字符串或字符串列表")


@dataclass
class Rule:
    """单条 YAML 检测规则。"""

    rule_id: str
    title: str
    category: str
    severity: RiskLevel
    scene: str
    match_type: str
    patterns: list[str]
    description: str
    remediation: str
    paths: list[str] = field(default_factory=list)
    file_types: list[str] = field(default_factory=list)
    mask: bool = False
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    enabled: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any], category: str) -> "Rule":
        if not isinstance(data, dict):
            raise RuleValidationError("规则必须是映射结构")
        category = str(data.get("category") or category).strip()
        if category not in VALID_CATEGORIES:
            raise RuleValidationError(f"未知规则分类: {category}")
        match_type = str(data.get("match_type", "")).strip().lower()
        if match_type not in VALID_MATCH_TYPES:
            raise RuleValidationError(f"match_type 非法: {match_type}")
        patterns = _as_list(data.get("pattern"))
        if not patterns:
            raise RuleValidationError("缺少 pattern")
        rule = cls(
            rule_id=str(data.get("id", "")).strip().upper(),
            title=str(data.get("title") or data.get("id") or "").strip(),
            category=category,
            severity=RiskLevel.parse(data.get("severity", "")),
            scene=str(data.get("scene", "")).strip(),
            match_type=match_type,
            patterns=patterns,
            description=str(data.get("description", "")).strip(),
            remediation=str(data.get("remediation", "")).strip(),
            paths=_as_list(data.get("paths")),
            file_types=[item.lower() for item in _as_list(data.get("file_types"))],
            mask=bool(data.get("mask", False)),
            tags=_as_list(data.get("tags")),
            metadata=data.get("metadata") or {},
            enabled=bool(data.get("enabled", True)),
        )
        rule.validate()
        return rule

    def validate(self) -> None:
        required = {
            "id": self.rule_id,
            "scene": self.scene,
            "description": self.description,
            "remediation": self.remediation,
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise RuleValidationError(f"缺少必填字段: {', '.join(missing)}")
        if not RULE_ID_PATTERN.match(self.rule_id):
            raise RuleValidationError(f"规则 ID 非法: {self.rule_id}")
        if not isinstance(self.metadata, dict):
            raise RuleValidationError("metadata 必须为映射")
        if self.match_type == "regex":
            self._validate_regex()
        if self.match_type == "hash":
            self._validate_hash()

    def _validate_regex(self) -> None:
        for pattern in self.patterns:
            if len(pattern) > 4000:
                raise RuleValidationError("正则表达式过长")
            if re.search(r"\([^()]*[+*][^()]*\)[+*{]", pattern):
                raise RuleValidationError("正则包含高风险嵌套量词，已拒绝")
            try:
                re.compile(pattern)
            except re.error as exc:
                raise RuleValidationError(f"正则表达式非法: {exc}") from exc

    def _validate_hash(self) -> None:
        for pattern in self.patterns:
            if not re.fullmatch(r"[0-9a-fA-F]{64}", pattern):
                raise RuleValidationError("hash 规则必须使用 64 位 SHA-256")

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "match_type": self.match_type,
        }
