"""凭证打码工具测试。"""

from firm_audit.utils.mask_util import mask_secret, redact_text


def test_mask_secret_keeps_two_edges():
    assert mask_secret("Fw-S3cure-2024!") == "Fw***********4!"
    assert mask_secret("abcdef") == "ab**ef" and mask_secret("abc") == "****"
    assert mask_secret("") == ""


def test_redact_common_secret_shapes():
    assert "Db9#" not in redact_text("password=Db9#vaultKey")
    assert "Db9#" not in redact_text('secret = "Db9#vaultKey"')
    masked = redact_text("mysql://admin:Db9#vaultKey@127.0.0.1/db")
    assert "admin:Db9#" not in masked and "@127.0.0.1" in masked
    shadow = "root:$1$abc$hashvalue:19000:0:99999:7:::"
    assert "$1$abc$hashvalue" not in redact_text(shadow) and "root:" in redact_text(shadow)
    assert "abcdefghijklmnop" not in redact_text("Bearer abcdefghijklmnop")
    assert redact_text("") == "" and redact_text("hello world") == "hello world"
