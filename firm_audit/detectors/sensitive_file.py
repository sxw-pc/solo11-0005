"""敏感文件检测：权限暴露时自动提升风险等级。"""

from __future__ import annotations

import os
import stat

from firm_audit.models.finding import Finding
from firm_audit.models.rule import RiskLevel

from .base import BaseDetector, register_detector


@register_detector
class SensitiveFileDetector(BaseDetector):
    category = "sensitive_file"

    def enrich(self, finding: Finding, scan_file) -> Finding:
        if os.name == "posix":
            exposures = []
            if scan_file.is_world_writable:
                exposures.append("全局可写")
            if scan_file.is_world_readable:
                exposures.append("全局可读")
            if exposures:
                finding.metadata["permission"] = f"{stat.S_IMODE(scan_file.mode):04o}"
                finding.metadata["permission_exposure"] = exposures
                finding.severity = RiskLevel.HIGH
        finding.metadata["sensitive_type"] = finding.tags[0] if finding.tags else "file"
        return super().enrich(finding, scan_file)
