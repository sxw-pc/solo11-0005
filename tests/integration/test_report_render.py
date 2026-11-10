"""报告生成与脱敏回归测试。"""

import json

import pytest

from firm_audit.core.scanner import Scanner, ScanResult
from firm_audit.models.task import ScanOptions
from firm_audit.report import (
    build_report_data, render_html, render_json, render_markdown, report_filename, write_reports,
)
from firm_audit.report.report_data import LEGAL_NOTICE


@pytest.fixture(scope="module")
def result(firmware_dir):
    return Scanner(ScanOptions(target=str(firmware_dir)), task_id="reporttask").scan()


def test_report_data_metadata_and_masking(result):
    data = build_report_data(result)
    assert data["tool"]["name"] == "固漏巡检仪" and data["legal_notice"] == LEGAL_NOTICE
    assert data["summary"]["total"] == 12 and data["summary"]["by_severity"]["high"] == 11
    assert len(data["summary"]["by_category"]) == 4
    raw = json.dumps(data, ensure_ascii=False)
    for secret in ("Fw-S3cure-2024!", "Db9#vaultKey", "admin:$1$"):
        assert secret not in raw
    data["findings"][0]["evidence"]["snippet"] = "password=LeakMe123"
    data["warnings"].append("token=WarnLeak456")
    assert build_report_data(result)["findings"]


def test_renderers_complete_offline_and_escaping(result, tmp_path):
    data = build_report_data(result)
    assert json.loads(render_json(data))["summary"]["total"] == 12
    markdown = render_markdown(data)
    assert "风险统计" in markdown and "修复建议" in markdown
    assert "<details>" in markdown and "合规提示" in markdown
    html = render_html(data)
    assert "<!doctype html>" in html.lower()
    assert "http://" not in html.replace("http://127.0.0.1", "") and "https://" not in html
    assert "<script src=" not in html and "固件文件系统静态安全巡检报告" in html
    assert "Fw-S3cure-2024!" not in html
    empty = ScanResult(task_id="empty", target=str(tmp_path),
                       options=ScanOptions(target=str(tmp_path)),
                       started_at="2026-01-01T00:00:00+00:00",
                       finished_at="2026-01-01T00:00:01+00:00", duration_seconds=1.0,
                       files_total=0, files_scanned=0, files_skipped=0, total_bytes=0,
                       scanned_bytes=0, rules_loaded=57, rule_version="1.0.0",
                       warnings=["<script>alert(1)</script>"])
    empty_markdown = render_markdown(build_report_data(empty))
    assert "未发现命中项" in empty_markdown and "&lt;script&gt;" in empty_markdown
    assert "<script>alert(1)</script>" not in render_html(build_report_data(empty))


def test_report_filenames_and_write_formats(result, tmp_path):
    assert report_filename("../../evil", "json") == "firm_audit_evil.json"
    assert report_filename("abc", "md") == "firm_audit_abc.md"
    with pytest.raises(ValueError):
        report_filename("abc", "pdf")
    outputs = write_reports(result, tmp_path / "out", ["json", "html"])
    assert set(outputs) == {"json", "html"} and all(path.is_file() for path in outputs.values())
    with pytest.raises(ValueError):
        write_reports(result, tmp_path / "bad", ["pdf"])
