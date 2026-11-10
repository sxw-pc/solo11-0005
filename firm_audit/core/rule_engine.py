"""YAML 规则加载、格式校验与多类型匹配调度。"""

from __future__ import annotations

import fnmatch
import re
import stat
from pathlib import Path
from typing import Any, Iterable

import yaml

from firm_audit.models.finding import Evidence, Finding
from firm_audit.models.rule import Rule, RuleValidationError
from firm_audit.utils.mask_util import mask_secret, redact_text

MAX_RULE_FILE_BYTES = 1024 * 1024
MAX_RULES = 2000
SECRET_GROUPS = {"secret", "password", "passwd", "token", "value"}
BUILTIN_RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


class RuleEngine:
    """规则集与匹配引擎。"""

    def __init__(
        self,
        rules: Iterable[Rule],
        warnings: list[str] | None = None,
        version: str = "1.0.0",
    ) -> None:
        self.rules = list(rules)
        self.warnings = list(warnings or [])
        self.version = version
        self._regex_cache: dict[str, list[re.Pattern]] = {}

    @classmethod
    def from_directories(
        cls, builtin: Path | None = None, custom: Path | None = None
    ) -> "RuleEngine":
        directories = [builtin or BUILTIN_RULES_DIR]
        if custom is not None:
            directories.append(Path(custom))
        rules: list[Rule] = []
        warnings: list[str] = []
        versions: set[str] = set()
        for directory in directories:
            loaded, notes, doc_versions = _load_directory(directory)
            rules.extend(loaded)
            warnings.extend(notes)
            versions.update(doc_versions)
        unique: list[Rule] = []
        seen: set[str] = set()
        for rule in rules:
            if rule.rule_id in seen:
                warnings.append(f"重复规则 ID 已跳过: {rule.rule_id}")
                continue
            seen.add(rule.rule_id)
            unique.append(rule)
        if len(unique) > MAX_RULES:
            warnings.append(f"规则数量超过 {MAX_RULES}，仅加载前 {MAX_RULES} 条")
            unique = unique[:MAX_RULES]
        version = ",".join(sorted(versions)) or "1.0.0"
        return cls(unique, warnings, version)

    def rules_for(self, category: str | None = None) -> list[Rule]:
        return [
            rule
            for rule in self.rules
            if rule.enabled and (category is None or rule.category == category)
        ]

    def evaluate(self, scan_file, category: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self.rules_for(category):
            if not self._applies(rule, scan_file):
                continue
            finding = self._match_rule(rule, scan_file)
            if finding is not None:
                findings.append(finding)
        return findings

    def _applies(self, rule: Rule, scan_file) -> bool:
        if rule.file_types and "any" not in rule.file_types:
            kind = "binary" if scan_file.is_binary else "text"
            if kind not in rule.file_types:
                return False
        if rule.match_type != "path" and rule.paths:
            return self._path_hit(scan_file.rel_path, rule.paths)
        return True

    @staticmethod
    def _path_hit(rel_path: str, patterns: Iterable[str]) -> bool:
        name = Path(rel_path).name
        normalized = rel_path.replace("\\", "/")
        return any(
            fnmatch.fnmatchcase(normalized, pattern)
            or fnmatch.fnmatchcase("/" + normalized, pattern)
            or fnmatch.fnmatchcase(name, pattern)
            for pattern in patterns
        )

    def _match_rule(self, rule: Rule, scan_file) -> Finding | None:
        matchers = {
            "exact": self._match_exact,
            "regex": self._match_regex,
            "permission": self._match_permission,
            "hash": self._match_hash,
            "path": self._match_path,
        }
        matched = matchers[rule.match_type](rule, scan_file)
        if matched is None:
            return None
        snippet, line, offset = matched
        return self._build_finding(rule, scan_file, snippet, line, offset)

    def _match_path(self, rule: Rule, scan_file) -> tuple[str, int, int] | None:
        if rule.paths and self._path_hit(scan_file.rel_path, rule.paths):
            return f"命中敏感路径: {scan_file.rel_path}", 0, 0
        return None

    def _match_hash(self, rule: Rule, scan_file) -> tuple[str, int, int] | None:
        if any(
            pattern.lower() == scan_file.sha256.lower() for pattern in rule.patterns
        ):
            return f"SHA-256: {scan_file.sha256}", 0, 0
        return None

    def _match_permission(self, rule: Rule, scan_file) -> tuple[str, int, int] | None:
        mode = scan_file.mode
        for pattern in rule.patterns:
            if _permission_matches(pattern, mode):
                text = f"文件权限 {stat.S_IMODE(mode):04o}，命中权限规则 {pattern}"
                return text, 0, 0
        return None

    def _match_exact(self, rule: Rule, scan_file) -> tuple[str, int, int] | None:
        for line, offset, text in _iter_content(scan_file):
            if any(pattern in text for pattern in rule.patterns):
                return text, line, offset
        return None

    def _match_regex(self, rule: Rule, scan_file) -> tuple[str, int, int] | None:
        for regex in self._compiled(rule):
            for line, offset, text in _iter_content(scan_file):
                match = regex.search(text)
                if match:
                    return _masked_match_line(match, text, rule), line, offset
        return None

    def _compiled(self, rule: Rule) -> list[re.Pattern]:
        if rule.rule_id not in self._regex_cache:
            self._regex_cache[rule.rule_id] = [
                re.compile(item) for item in rule.patterns
            ]
        return self._regex_cache[rule.rule_id]

    def _build_finding(
        self, rule: Rule, scan_file, snippet: str, line: int, offset: int
    ) -> Finding:
        snippet = snippet.strip()
        if len(snippet) > 300:
            snippet = snippet[:297] + "..."
        evidence_type = "byte" if scan_file.is_binary else "char"
        metadata = dict(rule.metadata)
        metadata.update(
            {
                "match_type": rule.match_type,
                "evidence_type": evidence_type,
                "binary_offset": offset if scan_file.is_binary else None,
            }
        )
        return Finding(
            rule_id=rule.rule_id,
            title=rule.title,
            category=rule.category,
            severity=rule.severity,
            file_path=scan_file.rel_path,
            evidence=Evidence(snippet=snippet, line=line, offset=offset),
            description=rule.description,
            remediation=rule.remediation,
            scene=rule.scene,
            tags=list(rule.tags),
            metadata=metadata,
        )


def _iter_content(scan_file):
    if scan_file.is_binary:
        for item in scan_file.strings:
            yield 0, item.offset, item.value
        return
    offset = 0
    for number, line in enumerate(scan_file.lines, start=1):
        yield number, offset, line
        offset += len(line) + 1


def _masked_match_line(match: re.Match, line: str, rule: Rule) -> str:
    replacements = []
    for name in SECRET_GROUPS:
        try:
            value = match.group(name)
        except (IndexError, KeyError):
            continue
        if value:
            replacements.append(value)
    masked = line
    for value in sorted(set(replacements), key=len, reverse=True):
        masked = masked.replace(value, mask_secret(value))
    if rule.category == "hardcode_cred" or rule.mask:
        masked = redact_text(masked)
    return masked


def _permission_matches(pattern: str, mode: int) -> bool:
    token = pattern.strip().lower()
    if token == "world_writable":
        return bool(mode & stat.S_IWOTH)
    if token == "world_readable":
        return bool(mode & stat.S_IROTH)
    if token == "any_world":
        return bool(mode & (stat.S_IWOTH | stat.S_IROTH))
    try:
        expected = int(token, 8) if token.startswith("0") else int(token, 8)
        return stat.S_IMODE(mode) == expected
    except ValueError:
        return False


def _load_yaml(path: Path) -> tuple[Any, list[str]]:
    if path.stat().st_size > MAX_RULE_FILE_BYTES:
        return None, [f"规则文件过大已跳过: {path.name}"]
    try:
        with path.open("r", encoding="utf-8") as handle:
            return yaml.safe_load(handle), []
    except (OSError, yaml.YAMLError) as exc:
        return None, [f"规则文件解析失败已跳过 {path.name}: {exc}"]


def _load_directory(directory: Path) -> tuple[list[Rule], list[str], set[str]]:
    rules: list[Rule] = []
    warnings: list[str] = []
    versions: set[str] = set()
    if not directory.is_dir():
        return rules, [f"规则目录不存在已跳过: {directory}"], versions
    for path in sorted(directory.glob("*.yaml")):
        document, notes = _load_yaml(path)
        warnings.extend(notes)
        if not isinstance(document, dict):
            warnings.append(f"规则文件结构非法已跳过: {path.name}")
            continue
        category = str(document.get("category") or path.stem)
        versions.add(str(document.get("version", "1.0.0")))
        entries = document.get("rules", [])
        if not isinstance(entries, list):
            warnings.append(f"rules 必须为列表: {path.name}")
            continue
        for index, entry in enumerate(entries, start=1):
            try:
                rules.append(Rule.from_dict(entry, category))
            except (RuleValidationError, TypeError) as exc:
                warnings.append(f"{path.name} 第 {index} 条规则无效已跳过: {exc}")
    return rules, warnings, versions
