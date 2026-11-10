"""CLI 端到端测试，全程离线。"""

import json

from firm_audit import cli


def test_scan_command_generates_three_reports(firmware_dir, tmp_path, capsys):
    output = tmp_path / "report"
    assert cli.main(["scan", "--target", str(firmware_dir), "--output", str(output)]) == 0
    stdout = capsys.readouterr().out
    assert "命中 12 项" in stdout and "高危 11" in stdout
    assert sorted(path.suffix for path in output.iterdir()) == [".html", ".json", ".md"]
    payload = json.loads(next(output.glob("*.json")).read_text(encoding="utf-8"))
    assert payload["summary"]["total"] == 12
    assert "Fw-S3cure-2024!" not in json.dumps(payload, ensure_ascii=False)


def test_scan_with_custom_rules_and_formats(firmware_dir, custom_rules_dir, tmp_path):
    output = tmp_path / "r"
    args = ["scan", "--target", str(firmware_dir), "--output", str(output),
            "--rules-dir", str(custom_rules_dir), "--formats", "json"]
    assert cli.main(args) == 0
    assert [path.suffix for path in output.iterdir()] == [".json"]
    payload = json.loads(next(output.glob("*.json")).read_text(encoding="utf-8"))
    assert any(item["rule_id"] == "CUSTOM-001" for item in payload["findings"])


def test_scan_errors_and_large_target_confirmation(firmware_dir, tmp_path, monkeypatch, capsys):
    assert cli.main(["scan", "--target", str(tmp_path / "missing")]) == 2
    assert "不存在" in capsys.readouterr().err
    bad_format = ["scan", "--target", str(firmware_dir), "--output", str(tmp_path / "r1"),
                  "--formats", "pdf"]
    assert cli.main(bad_format) == 2 and "报告格式非法" in capsys.readouterr().err
    monkeypatch.setattr(cli, "MAX_SURVEY_FILES", 0)
    args = ["scan", "--target", str(firmware_dir), "--output", str(tmp_path / "r2")]
    assert cli.main(args) == 2 and "追加 --yes" in capsys.readouterr().err
    assert cli.main(args + ["--yes"]) == 0 and "目标较大" in capsys.readouterr().err


def test_cleanup_and_web_guards(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("FIRM_AUDIT_HOME", str(tmp_path / "home"))
    assert cli.main(["cleanup"]) == 2 and "追加 --yes" in capsys.readouterr().err
    from firm_audit.core.storage import data_home

    data_home()
    assert cli.main(["cleanup", "--yes"]) == 0 and "已清理" in capsys.readouterr().out
    assert cli.main(["web", "--host", "0.0.0.0"]) == 2
    assert "仅允许" in capsys.readouterr().err
    assert cli.main(["web", "--host", "bad-host"]) == 2
    assert cli.main(["web", "--port", "0"]) == 2
