"""扫描编排测试。"""

import zipfile

import pytest

from firm_audit.core.path_validator import PathValidationError
from firm_audit.core.scanner import Scanner
from firm_audit.models.task import ScanOptions


def test_scan_fixture_exactly_twelve(firmware_dir):
    scanner = Scanner(ScanOptions(target=str(firmware_dir)), task_id="fixturetask")
    result = scanner.scan()
    assert len(result.findings) == 12
    assert result.risk_counts == {"high": 11, "medium": 1, "low": 0}
    assert result.category_counts == {
        "hardcode_cred": 3, "sensitive_file": 3,
        "insecure_config": 2, "debug_interface": 4,
    }
    assert result.files_scanned >= 11
    assert result.rule_version == "1.0.0" and result.rules_loaded == 57
    assert {item.rule_id for item in result.findings} >= {
        "HCRED-001", "CONF-001", "SENS-002", "DBG-003"}
    assert len({item.key for item in result.findings}) == 12


def test_custom_rules_progress_archive_failure_and_guards(
        tmp_path, firmware_dir, custom_rules_dir):
    events = []
    options = ScanOptions(target=str(firmware_dir), rules_dir=str(custom_rules_dir))
    result = Scanner(options, progress=events.append).scan()
    assert len(result.findings) == 13
    assert any(item.rule_id == "CUSTOM-001" for item in result.findings)
    assert events[-1]["progress"] == 100 and events[-1]["phase"] == "扫描完成"
    assert result.warnings == []
    archive = tmp_path / "pack.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("etc/sshd_config", "PermitRootLogin yes\n")
        bundle.writestr("www/index.html", "hello\n")
    archived = Scanner(ScanOptions(target=str(tmp_path), extract_archives=True)).scan()
    assert [item.rule_id for item in archived.findings] == ["CONF-001"]
    assert archived.findings[0].file_path.startswith("pack.zip!/etc/")
    assert archived.files_total == 2
    broken_dir = tmp_path / "broken_dir"
    broken_dir.mkdir()
    (broken_dir / "broken.zip").write_bytes(b"PK\x03\x04broken")
    failed = Scanner(ScanOptions(target=str(broken_dir), extract_archives=True)).scan()
    assert failed.findings == [] and any("解包失败" in item for item in failed.warnings)
    with pytest.raises(PathValidationError):
        Scanner(ScanOptions(target=str(tmp_path / "missing"))).scan()
    with pytest.raises(PathValidationError):
        Scanner(ScanOptions(target=str(tmp_path), rules_dir=str(tmp_path / "no-rules"))).scan()
    scanner = Scanner(ScanOptions(target=str(firmware_dir / "etc" / "shadow")))
    result = scanner.scan()
    assert len(result.findings) == 2 and result.files_total == 1
    assert scanner._dedupe(result.findings + result.findings) == result.findings
