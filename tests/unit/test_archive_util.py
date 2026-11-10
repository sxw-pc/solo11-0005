"""安全解包测试，覆盖 Zip Slip、符号链接与解压炸弹防护。"""

import io
import tarfile
import zipfile

import pytest

from firm_audit.utils import archive_util
from firm_audit.utils.archive_util import (
    ArchiveExtractionError, _copy_limited, _safe_member, cleanup_directory, safe_extract,
)


def write_zip(path, members):
    with zipfile.ZipFile(path, "w") as bundle:
        for name, data, mode in members:
            info = zipfile.ZipInfo(name)
            info.external_attr = mode << 16
            bundle.writestr(info, data)


def test_safe_zip_extract_and_cleanup(tmp_path):
    archive = tmp_path / "ok.zip"
    write_zip(archive, [("etc/a.conf", b"x=1", 0o100644), ("empty/", b"", 0o40755)])
    out = tmp_path / "out"
    safe_extract(archive, out)
    assert (out / "etc" / "a.conf").read_bytes() == b"x=1" and (out / "empty").is_dir()
    cleanup_directory(out)
    assert not out.exists()
    cleanup_directory(out)


def test_zip_traversal_symlink_and_limits(tmp_path, monkeypatch):
    bad = tmp_path / "bad.zip"
    write_zip(bad, [("../escape.txt", b"bad", 0o100644)])
    with pytest.raises(ArchiveExtractionError, match="越界"):
        safe_extract(bad, tmp_path / "o1")
    link = tmp_path / "link.zip"
    write_zip(link, [("link", b"/etc/passwd", 0o120777)])
    with pytest.raises(ArchiveExtractionError, match="符号链接"):
        safe_extract(link, tmp_path / "o2")
    many = tmp_path / "many.zip"
    write_zip(many, [("a", b"a", 0o100644), ("b", b"b", 0o100644)])
    monkeypatch.setattr(archive_util, "MAX_MEMBERS", 1)
    with pytest.raises(ArchiveExtractionError, match="成员数量"):
        safe_extract(many, tmp_path / "o3")
    monkeypatch.setattr(archive_util, "MAX_MEMBERS", 99)
    monkeypatch.setattr(archive_util, "MAX_UNCOMPRESSED", 1)
    with pytest.raises(ArchiveExtractionError, match="体积"):
        safe_extract(many, tmp_path / "o4")


def test_tar_extract_traversal_link_limits_and_helpers(tmp_path, monkeypatch):
    good = tmp_path / "good.tar"
    with tarfile.open(good, "w") as bundle:
        for name, data in (("etc/a.conf", b"abc"), ("b", b"x")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            bundle.addfile(info, io.BytesIO(data))
    out = tmp_path / "tarout"
    safe_extract(good, out)
    assert (out / "etc" / "a.conf").read_bytes() == b"abc"
    for name, link, kind in (("../bad", "", None), ("link", "/etc/passwd", tarfile.SYMTYPE)):
        archive = tmp_path / ("bad.tar" if kind is None else "link.tar")
        with tarfile.open(archive, "w") as bundle:
            info = tarfile.TarInfo(name)
            if kind is None:
                info.size = 1
                bundle.addfile(info, io.BytesIO(b"x"))
            else:
                info.type = kind
                info.linkname = link
                bundle.addfile(info)
        with pytest.raises(ArchiveExtractionError):
            safe_extract(archive, tmp_path / "t1")
    plain = tmp_path / "plain.bin"
    plain.write_bytes(b"not an archive")
    with pytest.raises(ArchiveExtractionError, match="不支持"):
        safe_extract(plain, tmp_path / "t3")
    monkeypatch.setattr(archive_util, "MAX_MEMBERS", 1)
    with pytest.raises(ArchiveExtractionError, match="成员数量"):
        safe_extract(good, tmp_path / "lim1")
    monkeypatch.setattr(archive_util, "MAX_MEMBERS", 99)
    monkeypatch.setattr(archive_util, "MAX_UNCOMPRESSED", 1)
    with pytest.raises(ArchiveExtractionError, match="体积"):
        safe_extract(good, tmp_path / "lim2")
    for bad in ("/abs", "../x", "a/../../b", ""):
        with pytest.raises(ArchiveExtractionError):
            _safe_member(bad)
    with pytest.raises(ArchiveExtractionError, match="体积"):
        _copy_limited(io.BytesIO(b"abcdef"), tmp_path / "copy", 2)
    assert (tmp_path / "copy").read_bytes() == b""
    assert _copy_limited(io.BytesIO(b"abcdef"), tmp_path / "copy2", 10) == 6
    assert (tmp_path / "copy2").read_bytes() == b"abcdef"
