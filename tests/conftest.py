"""测试公共夹具，仅使用本地虚构固件与规则。"""

from __future__ import annotations

from pathlib import Path

import pytest

from firm_audit.core.file_filter import ScanFile
from firm_audit.core.rule_engine import RuleEngine

FIXTURES = Path(__file__).resolve().parent / "fixtures"
MOCK_FIRMWARE = FIXTURES / "mock_firmware"
MOCK_RULES = FIXTURES / "mock_rules"


@pytest.fixture(scope="session")
def firmware_dir() -> Path:
    assert MOCK_FIRMWARE.is_dir()
    return MOCK_FIRMWARE


@pytest.fixture(scope="session")
def custom_rules_dir() -> Path:
    return MOCK_RULES


@pytest.fixture(scope="session")
def engine() -> RuleEngine:
    return RuleEngine.from_directories()


@pytest.fixture
def make_scan_file(tmp_path):
    def factory(text: str = "", rel_path: str = "etc/sample.conf", *, mode: int = 0o644,
                binary: bool = False, strings: tuple = (), sha256: str = "0" * 64) -> ScanFile:
        path = tmp_path / "sample.bin"
        path.write_bytes(text.encode("utf-8") if not binary else b"\x00")
        return ScanFile(path=path, rel_path=rel_path, size=len(text.encode("utf-8")), mode=mode,
                        mime="application/octet-stream" if binary else "text/plain",
                        kind="binary" if binary else "text", is_binary=binary, sha256=sha256,
                        text="" if binary else text,
                        lines=() if binary else tuple(text.splitlines()), strings=strings)

    return factory


@pytest.fixture
def clean_file(make_scan_file):
    return make_scan_file("nothing interesting here\n", "etc/normal.conf")
