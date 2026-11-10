"""硬编码凭证检测：对证据片段执行强制打码。"""

from __future__ import annotations

from firm_audit.models.finding import Finding
from firm_audit.utils.mask_util import redact_text

from .base import BaseDetector, register_detector


@register_detector
class HardcodeCredDetector(BaseDetector):
    category = "hardcode_cred"

    def enrich(self, finding: Finding, scan_file) -> Finding:
        finding.evidence.snippet = redact_text(finding.evidence.snippet)
        finding.metadata.update(
            {
                "masked": True,
                "credential_type": finding.tags[0] if finding.tags else "generic",
            }
        )
        return super().enrich(finding, scan_file)
