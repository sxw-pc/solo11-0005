"""不安全服务配置检测。"""

from __future__ import annotations

from firm_audit.models.finding import Finding

from .base import BaseDetector, register_detector


@register_detector
class InsecureConfigDetector(BaseDetector):
    category = "insecure_config"

    def enrich(self, finding: Finding, scan_file) -> Finding:
        finding.metadata.setdefault("config_file", scan_file.rel_path)
        finding.metadata.setdefault("current_value", finding.evidence.snippet)
        finding.metadata["service"] = finding.tags[0] if finding.tags else "generic"
        return super().enrich(finding, scan_file)
