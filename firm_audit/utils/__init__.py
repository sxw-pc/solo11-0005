"""通用工具模块。"""

from .encoding_util import decode_bytes, read_text_file
from .file_header import detect_file_type, is_probably_binary, read_head
from .hash_util import dedupe, sha256_bytes, sha256_file
from .mask_util import mask_secret, redact_text
from .string_extractor import ExtractedString, extract_file_strings, extract_strings

__all__ = [
    "ExtractedString",
    "decode_bytes",
    "dedupe",
    "detect_file_type",
    "extract_file_strings",
    "extract_strings",
    "is_probably_binary",
    "mask_secret",
    "read_head",
    "read_text_file",
    "redact_text",
    "sha256_bytes",
    "sha256_file",
]
