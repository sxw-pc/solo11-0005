"""二进制字符串提取测试。"""

from firm_audit.utils.string_extractor import extract_file_strings, extract_strings


def test_extract_ascii_utf16_and_file(tmp_path):
    data = b"\x00abcd\x00" + "token".encode("utf-16-le")
    found = extract_strings(data)
    assert "abcd" in {item.value for item in found}
    assert any(item.encoding == "utf-16-le" for item in found)
    assert found == sorted(found, key=lambda item: (item.offset, item.encoding))
    assert extract_strings(b"") == [] and extract_strings(b"ab", min_length=2)[0].value == "ab"
    path = tmp_path / "blob.bin"
    path.write_bytes(b"\x00TOKEN_VALUE\x00")
    assert "TOKEN_VALUE" in {item.value for item in extract_file_strings(path)}
