"""专项检测器加载与注册。"""

from .base import (
    BaseDetector,
    build_detectors,
    register_detector,
    registered_categories,
)
from .debug_interface import DebugInterfaceDetector
from .hardcode_cred import HardcodeCredDetector
from .insecure_config import InsecureConfigDetector
from .sensitive_file import SensitiveFileDetector

__all__ = [
    "BaseDetector",
    "DebugInterfaceDetector",
    "HardcodeCredDetector",
    "InsecureConfigDetector",
    "SensitiveFileDetector",
    "build_detectors",
    "register_detector",
    "registered_categories",
]
