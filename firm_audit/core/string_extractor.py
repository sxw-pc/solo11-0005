"""兼容入口：二进制字符串提取实现位于 utils.string_extractor。"""

from firm_audit.utils.string_extractor import (
    ExtractedString,
    extract_file_strings,
    extract_strings,
)

__all__ = ["ExtractedString", "extract_file_strings", "extract_strings"]
