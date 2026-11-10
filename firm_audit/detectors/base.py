"""检测器基类与注册器，新增模块可零改动接入规则引擎。"""

from __future__ import annotations

from firm_audit.core.rule_engine import RuleEngine
from firm_audit.models.finding import Finding


class BaseDetector:
    category = ""

    def __init__(self, engine: RuleEngine) -> None:
        if not self.category:
            raise ValueError("检测器必须声明 category")
        self.engine = engine

    def detect(self, scan_file) -> list[Finding]:
        findings = self.engine.evaluate(scan_file, self.category)
        return [self.enrich(finding, scan_file) for finding in findings]

    def enrich(self, finding: Finding, scan_file) -> Finding:
        finding.metadata["category_label"] = finding.category_label
        return finding


_DETECTORS: dict[str, type[BaseDetector]] = {}


def register_detector(detector_cls: type[BaseDetector]) -> type[BaseDetector]:
    if not detector_cls.category:
        raise ValueError("检测器缺少 category")
    _DETECTORS[detector_cls.category] = detector_cls
    return detector_cls


def build_detectors(engine: RuleEngine) -> list[BaseDetector]:
    return [detector_cls(engine) for _, detector_cls in sorted(_DETECTORS.items())]


def registered_categories() -> list[str]:
    return sorted(_DETECTORS)
