"""哈希与去重测试。"""

import hashlib

from firm_audit.utils.hash_util import dedupe, sha256_bytes, sha256_file


def test_sha256_and_dedupe(tmp_path):
    data = b"firmware"
    assert sha256_bytes(data) == hashlib.sha256(data).hexdigest()
    path = tmp_path / "f.bin"
    path.write_bytes(data)
    assert sha256_file(path) == sha256_bytes(data)
    assert sha256_file(path, chunk_size=2) == sha256_bytes(data)
    items = [{"id": 1, "v": "a"}, {"id": 1, "v": "b"}, {"id": 2, "v": "c"}]
    assert [item["v"] for item in dedupe(items, key=lambda item: item["id"])] == ["a", "c"]
    assert dedupe([], key=str) == []
