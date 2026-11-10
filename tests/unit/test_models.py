"""数据模型测试。"""

import pytest

from firm_audit.models.finding import Evidence, Finding, severity_counts, sort_findings
from firm_audit.models.rule import RiskLevel, Rule, RuleValidationError
from firm_audit.models.task import ScanOptions, ScanTask


def make_rule(**overrides):
    data = dict(id="TEST-001", title="测试", category="insecure_config", severity="high",
                scene="场景", match_type="exact", pattern="bad", description="描述", remediation="修复")
    data.update(overrides)
    return Rule.from_dict(data, "insecure_config")


def test_risk_level_and_rule_validation():
    assert RiskLevel.parse("高危") is RiskLevel.HIGH and RiskLevel.LOW.label == "低危"
    assert RiskLevel.parse("Medium").weight == 2
    with pytest.raises(RuleValidationError):
        RiskLevel.parse("critical")
    rule = make_rule(paths=["**/*.conf"], file_types=["TEXT"], tags=["ssh"])
    assert rule.paths == ["**/*.conf"] and rule.file_types == ["text"]
    assert rule.summary()["id"] == "TEST-001"
    bad = [{"id": "bad id"}, {"severity": "unknown"}, {"pattern": ""}, {"id": "../../EVIL"},
           {"match_type": "unknown"}, {"match_type": "regex", "pattern": "("},
           {"match_type": "regex", "pattern": "(a+)+"},
           {"match_type": "regex", "pattern": "a" * 4001},
           {"match_type": "hash", "pattern": "abc"}, {"pattern": 123}, {"metadata": ["bad"]}]
    for overrides in bad:
        with pytest.raises((RuleValidationError, TypeError)):
            make_rule(**overrides)
    with pytest.raises(RuleValidationError):
        Rule.from_dict([], "insecure_config")
    with pytest.raises(RuleValidationError):
        Rule.from_dict({"id": "X-1"}, "unknown_category")


def test_finding_serialization_and_sorting():
    high = Finding(rule_id="A-1", title="高", category="hardcode_cred", severity=RiskLevel.HIGH,
                   file_path="b.conf", evidence=Evidence("password=****", 3, 20), description="d",
                   remediation="r", tags=["ssh"], metadata={"x": 1})
    low = Finding(rule_id="B-1", title="低", category="unknown", severity=RiskLevel.LOW,
                  file_path="a.conf", evidence=Evidence("x", 1, 0), description="d", remediation="r")
    assert high.key == ("A-1", "b.conf") and high.category_label == "硬编码凭证"
    assert low.category_label == "unknown" and high.to_dict()["evidence"]["line"] == 3
    assert [item.rule_id for item in sort_findings([low, high])] == ["A-1", "B-1"]
    assert severity_counts([high, low]) == {"high": 1, "medium": 0, "low": 1}


def test_scan_options_and_task_snapshot():
    options = ScanOptions(target="./fw", formats=("JSON", "json", "md"))
    assert options.formats == ("json", "md") and options.max_size_bytes > 0
    assert options.to_dict()["target"] == "./fw"
    mapping = {"target": " ./fw ", "formats": "html,md", "max_depth": "3", "extract_archives": 1}
    parsed = ScanOptions.from_mapping(mapping)
    assert (parsed.formats, parsed.max_depth, parsed.extract_archives) == (("html", "md"), 3, True)
    for bad in ({"formats": ("pdf",)}, {"max_size_mb": 0}, {"max_depth": 65}):
        with pytest.raises(ValueError):
            ScanOptions(target="x", **bad)
    with pytest.raises(ValueError):
        ScanOptions.from_mapping({"target": "x", "formats": 1})
    task = ScanTask("abc123", ScanOptions(target="x"))
    snapshot = task.public()
    assert snapshot["status"] == "pending" and snapshot["options"]["target"] == "x"
    snapshot["options"]["target"] = "changed"
    assert task.options.target == "x"
