"""敏感信息打码工具，报告中禁止明文展示凭证。"""

from __future__ import annotations

import re

_SECRET_KEY = (
    r"password|passwd|pwd|pass|secret|token|api[_-]?key|apikey|"
    r"access[_-]?key|private[_-]?key|credential|auth[_-]?key"
)
_ASSIGN_RE = re.compile(rf"(?i)(\b(?:{_SECRET_KEY})\b\s*[:=]\s*)([\"']?)([^\s\"',;&]+)")
_URL_RE = re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://[^:\s/@]+:)([^@\s/]+)(@)")
_SHADOW_RE = re.compile(r"(^[^:\s]+:)(\$[^:\s]+)(?=:)")
_BEARER_RE = re.compile(r"(?i)(\bbearer\s+)([A-Za-z0-9._~+/=-]{6,})")


def mask_secret(value: str, visible: int = 2) -> str:
    """保留前 visible 位与后 visible 位，其余使用星号替代。"""
    text = str(value)
    if not text:
        return ""
    if len(text) <= visible * 2:
        return "*" * max(4, len(text))
    return text[:visible] + "*" * (len(text) - visible * 2) + text[-visible:]


def redact_text(text: str) -> str:
    """对常见凭证赋值、连接串、Bearer Token 做兜底打码。"""
    if not text:
        return ""
    result = _URL_RE.sub(
        lambda m: m.group(1) + mask_secret(m.group(2)) + m.group(3), text
    )
    result = _ASSIGN_RE.sub(
        lambda m: m.group(1) + m.group(2) + mask_secret(m.group(3)), result
    )
    result = _SHADOW_RE.sub(lambda m: m.group(1) + mask_secret(m.group(2)), result)
    return _BEARER_RE.sub(lambda m: m.group(1) + mask_secret(m.group(2)), result)
