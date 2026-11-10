"""文件类型探测测试。"""

import codecs

from firm_audit.utils.file_header import (
    detect_file_type, is_probably_binary, magic_from_head, read_head, suffix_kind,
)


def test_magic_suffix_and_detection():
    assert magic_from_head(b"\x7fELF....")[1] == "executable"
    assert magic_from_head(b"\x00" * 257 + b"ustar")[1] == "archive"
    assert magic_from_head(b"nope") is None
    assert suffix_kind("x.PNG")[1] == "image" and suffix_kind("x.unknown") is None
    assert detect_file_type("a.bin", b"\x7fELF")["is_binary"] is True
    utf16 = codecs.BOM_UTF16_LE + "abc".encode("utf-16-le")
    assert detect_file_type("a.dat", utf16)["kind"] == "text"
    assert detect_file_type("a.conf", b"key=value\n")["kind"] == "text"
    assert detect_file_type("a.dat", b"abc\x00def")["is_binary"] is True
    assert detect_file_type("a", b"")["source"] == "content"
    assert detect_file_type("a.zip", b"PK\x03\x04")["kind"] == "archive"
    assert detect_file_type("a.log", b"%PDF-1.7")["kind"] == "document"


def test_binary_heuristics_and_read_head(tmp_path):
    assert is_probably_binary(b"") is False
    assert is_probably_binary(b"MZ....") is True
    assert is_probably_binary(bytes(range(32)) * 10) is True
    path = tmp_path / "head.bin"
    path.write_bytes(b"X" * 100)
    assert read_head(path, 10) == b"X" * 10
    assert read_head(tmp_path / "missing") == b""
