"""文件遍历与加载测试。"""

from pathlib import Path

from firm_audit.core.file_filter import FileFilter, FileCandidate, survey


def test_collect_text_binary_skip_large_depth_and_archive(tmp_path):
    (tmp_path / "etc" / "deep").mkdir(parents=True)
    (tmp_path / "etc" / "a.conf").write_text("x=1\n", encoding="utf-8")
    (tmp_path / "etc" / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"x" * 2)
    (tmp_path / "etc" / "large.bin").write_bytes(b"x" * 50)
    (tmp_path / "etc" / "deep" / "b.sh").write_text("echo ok\n", encoding="utf-8")
    file_filter = FileFilter(tmp_path, max_size_bytes=20, max_depth=2)
    candidates = file_filter.collect()
    assert {item.rel_path for item in candidates} == {"etc/a.conf", "etc/deep/b.sh"}
    assert file_filter.skipped["large"] == 1 and file_filter.skipped["type"] == 1
    assert file_filter.total_bytes > 0 and FileFilter(tmp_path, 1000, max_depth=0).collect() == []
    archive = tmp_path / "etc" / "pack.zip"
    archive.write_bytes(b"PK\x03\x04dummy")
    collecting = FileFilter(tmp_path, 1000, max_depth=5, extract_archives=True)
    assert {item.rel_path for item in collecting.collect()} == {
        "etc/a.conf", "etc/deep/b.sh", "etc/large.bin"}
    assert [item.rel_path for item in collecting.archives] == ["etc/pack.zip"]
    single_path = tmp_path / "etc" / "deep" / "b.sh"
    single = FileFilter(single_path, 1000, max_depth=5)
    assert [item.rel_path for item in single.collect()] == ["b.sh"]
    assert single.total_bytes == single_path.stat().st_size


def test_load_text_binary_and_errors(tmp_path):
    text_path = tmp_path / "a.conf"
    text_path.write_bytes(b"secret=value\n")
    file_filter = FileFilter(tmp_path, 1000, 5)
    scan_file = file_filter.load(FileCandidate(text_path, "a.conf", 13, 0))
    assert scan_file.text == "secret=value\n" and scan_file.encoding == "utf-8"
    assert scan_file.lines == ("secret=value",) and not scan_file.is_binary
    blob = tmp_path / "blob.bin"
    blob.write_bytes(b"\x00TOKEN_VALUE\x00")
    binary = file_filter.load(FileCandidate(blob, "blob.bin", 14, 0))
    assert binary.is_binary and binary.text == ""
    assert "TOKEN_VALUE" in {item.value for item in binary.strings}
    image = tmp_path / "x.png"
    image.write_bytes(b"\x89PNG\r\n\x1a\n")
    assert file_filter.load(FileCandidate(image, "x.png", 8, 0)) is None
    assert file_filter.load(FileCandidate(tmp_path / "nope", "nope", 0, 0)) is None
    assert file_filter.warnings


def test_survey_file_and_directory(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "one.txt").write_text("123", encoding="utf-8")
    assert survey(tmp_path, 5) == {"files": 1, "bytes": 3}
    assert survey(tmp_path / "a" / "one.txt", 5) == {"files": 1, "bytes": 3}
    assert survey(Path(tmp_path / "missing"), 5)["files"] == 0
