"""编码探测测试。"""

import codecs

from firm_audit.utils.encoding_util import decode_bytes, read_text_file


def test_decode_known_encodings():
    assert decode_bytes("固件".encode()) == ("固件", "utf-8") and decode_bytes(b"") == ("", "utf-8")
    text, encoding = decode_bytes("固件配置".encode("gb18030"))
    assert text == "固件配置" and encoding == "gb18030"
    assert decode_bytes(b"caf\xe9") == ("café", "latin-1")
    assert decode_bytes(codecs.BOM_UTF16_LE + "密码".encode("utf-16-le"))[0] == "密码"
    assert decode_bytes(b"abc")[0] == "abc"


def test_utf16_without_bom_utf32_and_file(tmp_path):
    raw = "abc" * 40
    assert decode_bytes(raw.encode("utf-16-le"))[0] == raw
    assert decode_bytes(codecs.BOM_UTF32_LE + "x".encode("utf-32-le"))[0] == "x"
    assert isinstance(decode_bytes(b"\xef\xbb\xbf\xff")[0], str)
    path = tmp_path / "a.txt"
    path.write_bytes(b"abcdef")
    assert read_text_file(path, 3) == ("abc", "utf-8") and read_text_file(str(path))[0] == "abcdef"
