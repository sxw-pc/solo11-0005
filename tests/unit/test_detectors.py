"""检测器注册与增强逻辑测试。"""

import pytest

from firm_audit.detectors import sensitive_file as sensitive_module
from firm_audit.detectors import (
    BaseDetector, DebugInterfaceDetector, HardcodeCredDetector, InsecureConfigDetector,
    SensitiveFileDetector, build_detectors, register_detector, registered_categories,
)
from firm_audit.models.finding import Evidence, Finding
from firm_audit.models.rule import RiskLevel


def finding(category, tags=(), snippet="password=Sup3rSecret"):
    return Finding(rule_id="TEST-001", title="测试", category=category, severity=RiskLevel.MEDIUM,
                   file_path="etc/app.conf", evidence=Evidence(snippet=snippet, line=1),
                   description="d", remediation="r", tags=list(tags))


def test_registry_and_detector_build(engine):
    assert registered_categories() == ["debug_interface", "hardcode_cred",
                                       "insecure_config", "sensitive_file"]
    assert len(build_detectors(engine)) == 4
    with pytest.raises(ValueError, match="category"):
        BaseDetector(engine)
    with pytest.raises(ValueError, match="category"):
        register_detector(type("Broken", (BaseDetector,), {"category": ""}))


def test_hardcode_masking_and_permission_elevation(engine, clean_file, make_scan_file, monkeypatch):
    item = HardcodeCredDetector(engine).enrich(finding("hardcode_cred", ["password"]), clean_file)
    assert "Sup3rSecret" not in item.evidence.snippet
    assert item.metadata["masked"] is True and item.metadata["credential_type"] == "password"
    assert item.metadata["category_label"] == "硬编码凭证"
    scanner_file = make_scan_file("x", "etc/shadow", mode=0o666)
    detector = SensitiveFileDetector(engine)
    monkeypatch.setattr(sensitive_module.os, "name", "posix")
    item = detector.enrich(finding("sensitive_file", ["shadow"]), scanner_file)
    assert item.severity is RiskLevel.HIGH
    assert item.metadata["permission_exposure"] == ["全局可写", "全局可读"]
    assert item.metadata["sensitive_type"] == "shadow"


def test_config_and_debug_enrichment(engine, clean_file):
    config = InsecureConfigDetector(engine).enrich(finding("insecure_config", ["ssh"]), clean_file)
    assert config.metadata["config_file"] == "etc/normal.conf"
    assert config.metadata["service"] == "ssh" and config.metadata["category_label"] == "不安全配置"
    debug = DebugInterfaceDetector(engine).enrich(finding("debug_interface", ["account"]), clean_file)
    assert debug.metadata["interface_type"] == "account"
    assert debug.metadata["access_method"] == "系统账户/本地登录"
    assert "控制权" in debug.metadata["potential_impact"]
    generic = DebugInterfaceDetector(engine).enrich(finding("debug_interface", []), clean_file)
    assert generic.metadata["interface_type"] == "service"
