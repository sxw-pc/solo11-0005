"""遗留调试接口检测：补充访问方式、潜在危害与修复说明。"""

from __future__ import annotations

from firm_audit.models.finding import Finding

from .base import BaseDetector, register_detector

_CATEGORY_DEFAULTS = {
    "account": ("系统账户/本地登录", "攻击者可利用测试账户获取设备控制权"),
    "service": ("网络服务端口", "未移除的调试服务可被局域网内攻击者直接利用"),
    "binary": ("本地或网络命令入口", "调试开关或后门命令可能导致命令执行"),
    "web": ("HTTP 页面/接口", "暴露的调试页面可能泄露环境信息或被利用执行代码"),
}


@register_detector
class DebugInterfaceDetector(BaseDetector):
    category = "debug_interface"

    def enrich(self, finding: Finding, scan_file) -> Finding:
        interface_type = finding.tags[0] if finding.tags else "service"
        default_access, default_impact = _CATEGORY_DEFAULTS.get(
            interface_type, _CATEGORY_DEFAULTS["service"]
        )
        finding.metadata.setdefault("interface_type", interface_type)
        finding.metadata.setdefault("access_method", default_access)
        finding.metadata.setdefault("potential_impact", default_impact)
        return super().enrich(finding, scan_file)
