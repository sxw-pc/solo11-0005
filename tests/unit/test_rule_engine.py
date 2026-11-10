"""YAML 规则加载与匹配引擎测试。"""

import textwrap

from firm_audit.core import rule_engine as module
from firm_audit.core.rule_engine import RuleEngine, _permission_matches
from firm_audit.models.rule import Rule
from firm_audit.utils.string_extractor import ExtractedString


def rule(**overrides):
    data = {"id": "UNIT-001", "title": "单元测试规则", "category": "insecure_config",
            "severity": "high", "scene": "测试", "match_type": "exact", "pattern": "BAD_MARKER",
            "description": "描述", "remediation": "修复"}
    data.update(overrides)
    return Rule.from_dict(data, data["category"])


def test_builtin_rule_inventory(engine):
    assert len(engine.rules) == 57 and engine.warnings == []
    weak = [item for item in engine.rules_for("hardcode_cred") if item.rule_id == "HCRED-006"][0]
    assert weak.patterns[0].count("|") + 1 >= 120
    assert len(engine.rules_for("insecure_config")) == 28
    assert engine.rules_for("none") == [] and module.BUILTIN_RULES_DIR.is_dir()


def test_exact_regex_path_permission_hash_and_types(make_scan_file):
    exact = RuleEngine([rule()])
    assert exact.evaluate(make_scan_file("prefix BAD_MARKER suffix"))[0].evidence.line == 1
    secret_rule = rule(match_type="regex", pattern=r"password=(?P<secret>[A-Za-z0-9#]+)",
                       category="hardcode_cred")
    finding = RuleEngine([secret_rule]).evaluate(make_scan_file("x\npassword=Db9#vault"))[0]
    assert "Db9#vault" not in finding.evidence.snippet
    assert finding.evidence.line == 2 and finding.evidence.snippet.startswith("password=")
    path_rule = rule(match_type="path", paths=["**/shadow"], pattern="unused")
    finding = RuleEngine([path_rule]).evaluate(make_scan_file("", "etc/shadow"))[0]
    assert "敏感路径" in finding.evidence.snippet
    perm = rule(match_type="permission", pattern="world_writable")
    assert RuleEngine([perm]).evaluate(make_scan_file("x", mode=0o666))
    assert not RuleEngine([perm]).evaluate(make_scan_file("x", mode=0o644))
    for token, mode, expected in [("0644", 0o644, True), ("world_readable", 0o604, True),
                                  ("any_world", 0o600, False), ("invalid", 0o777, False)]:
        assert _permission_matches(token, mode) is expected
    digest = "a" * 64
    hash_rule = rule(match_type="hash", pattern=digest)
    assert RuleEngine([hash_rule]).evaluate(make_scan_file(sha256=digest))
    assert not RuleEngine([hash_rule]).evaluate(make_scan_file(sha256="b" * 64))
    scoped = RuleEngine([rule(file_types=["text"], paths=["*.conf"])])
    assert scoped.evaluate(make_scan_file("BAD_MARKER", "etc/x.conf"))
    assert not scoped.evaluate(make_scan_file("BAD_MARKER", "a.bin", binary=True))
    binary = make_scan_file(binary=True, strings=(ExtractedString(7, "BAD_MARKER", "ascii"),))
    hit = RuleEngine([rule(file_types=["binary"])]).evaluate(binary)[0]
    assert hit.evidence.offset == 7 and hit.metadata["evidence_type"] == "byte"


def test_snippet_truncation_and_mask_flag(make_scan_file):
    finding = RuleEngine([rule()]).evaluate(make_scan_file("BAD_MARKER " + "x" * 400))[0]
    assert len(finding.evidence.snippet) == 300 and finding.evidence.snippet.endswith("...")
    masked = rule(match_type="regex", pattern=r"token=[^\s]+", mask=True)
    finding = RuleEngine([masked]).evaluate(make_scan_file("token=verysecretvalue"))[0]
    assert "verysecretvalue" not in finding.evidence.snippet


def test_load_custom_directory_warnings(tmp_path):
    good = textwrap.dedent("""
        category: debug_interface
        version: "2.0"
        rules:
          - id: EXTRA-001
            title: 自定义
            severity: low
            scene: 扩展
            match_type: exact
            pattern: EXTRA_MARKER
            description: 扩展规则
            remediation: 修复
    """)
    (tmp_path / "good.yaml").write_text(good, encoding="utf-8")
    files = {"bad.yaml": "rules: [", "shape.yaml": "- not a mapping",
             "norules.yaml": "category: x\nrules: nope\n", "invalid.yaml": "rules:\n  - id: BAD\n"}
    for name, content in files.items():
        (tmp_path / name).write_text(content, encoding="utf-8")
    engine = RuleEngine.from_directories(custom=tmp_path)
    assert any(item.rule_id == "EXTRA-001" for item in engine.rules)
    assert "2.0" in engine.version and len(engine.warnings) >= 4
    missing = RuleEngine.from_directories(custom=tmp_path / "missing")
    assert any("不存在" in item for item in missing.warnings)


def test_duplicate_ids_limit_and_oversize_file(tmp_path, monkeypatch):
    content = textwrap.dedent("""
        category: insecure_config
        rules:
          - id: DUP-001
            title: 重复
            severity: low
            scene: 测试
            match_type: exact
            pattern: X
            description: 描述
            remediation: 修复
    """)
    (tmp_path / "a.yaml").write_text(content, encoding="utf-8")
    (tmp_path / "b.yaml").write_text(content, encoding="utf-8")
    engine = RuleEngine.from_directories(custom=tmp_path)
    assert [item.rule_id for item in engine.rules].count("DUP-001") == 1
    assert any("重复" in item for item in engine.warnings)
    monkeypatch.setattr(module, "MAX_RULES", 1)
    (tmp_path / "b.yaml").write_text(content.replace("DUP-001", "DUP-002"), encoding="utf-8")
    limited = RuleEngine.from_directories(custom=tmp_path)
    assert len(limited.rules) == 1 and any("超过" in item for item in limited.warnings)
    monkeypatch.setattr(module, "MAX_RULE_FILE_BYTES", 1)
    oversized = RuleEngine.from_directories(custom=tmp_path)
    assert any("过大" in item for item in oversized.warnings) and oversized.rules == []
