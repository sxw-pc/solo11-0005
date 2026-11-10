"""命令行入口：本地 Web 服务、单次扫描与数据清理。"""

from __future__ import annotations

import argparse
import ipaddress
import sys
import uuid

from firm_audit import DISCLAIMER, TOOL_NAME, __version__
from firm_audit.core.file_filter import survey
from firm_audit.core.path_validator import PathValidationError, validate_target
from firm_audit.core.scanner import Scanner
from firm_audit.core.storage import cleanup_data
from firm_audit.models.task import ALLOWED_FORMATS, ScanOptions
from firm_audit.report import write_reports

MAX_SURVEY_FILES = 5000
MAX_SURVEY_BYTES = 512 * 1024 * 1024


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="firm_audit", description=f"{TOOL_NAME} {__version__} 纯离线固件静态巡检"
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    web = subparsers.add_parser("web", help="启动本地 Web 服务")
    web.add_argument("--port", type=int, default=8080, help="监听端口（默认 8080）")
    web.add_argument(
        "--host", default="127.0.0.1", help="仅允许 127.0.0.1 或 ::1 环回地址"
    )

    scan = subparsers.add_parser("scan", help="执行单次离线扫描")
    scan.add_argument("--target", required=True, help="已解压固件目录或单文件")
    scan.add_argument("--output", default="./report", help="报告输出目录")
    scan.add_argument("--rules-dir", default=None, help="自定义 YAML 规则目录")
    scan.add_argument(
        "--max-size-mb", type=int, default=100, help="单文件大小阈值 MiB（1-2048）"
    )
    scan.add_argument("--max-depth", type=int, default=15, help="最大递归深度（1-64）")
    scan.add_argument(
        "--formats", default="json,md,html", help="报告格式，逗号分隔：json,md,html"
    )
    scan.add_argument(
        "--extract-archives", action="store_true", help="安全解包压缩包到临时目录并扫描"
    )
    scan.add_argument("--yes", action="store_true", help="目标过大时确认继续扫描")

    cleanup = subparsers.add_parser("cleanup", help="清理用户目录隐藏数据")
    cleanup.add_argument("--yes", action="store_true", help="确认清理")
    return parser


def _parse_formats(raw: str) -> tuple[str, ...]:
    formats = tuple(item.strip().lower() for item in raw.split(",") if item.strip())
    invalid = [item for item in formats if item not in ALLOWED_FORMATS]
    if invalid or not formats:
        raise ValueError(f"报告格式非法，仅支持: {', '.join(ALLOWED_FORMATS)}")
    return formats


def _check_survey(target: str, max_depth: int, confirmed: bool) -> None:
    resolved = validate_target(target)
    stats = survey(resolved, max_depth)
    if stats["files"] > MAX_SURVEY_FILES or stats["bytes"] > MAX_SURVEY_BYTES:
        print(
            f"目标较大：{stats['files']} 个文件，共 {stats['bytes']} 字节。",
            file=sys.stderr,
        )
        if not confirmed:
            raise ValueError("目标超过确认阈值，请检查后追加 --yes 继续")


def _run_scan(args: argparse.Namespace) -> int:
    formats = _parse_formats(args.formats)
    _check_survey(args.target, args.max_depth, args.yes)
    options = ScanOptions(
        target=args.target,
        rules_dir=args.rules_dir,
        max_size_mb=args.max_size_mb,
        max_depth=args.max_depth,
        formats=formats,
        output_dir=args.output,
        extract_archives=args.extract_archives,
    )
    print(f"{TOOL_NAME} v{__version__} - 纯离线静态扫描")
    print(f"合规提示：{DISCLAIMER}")
    result = Scanner(options, task_id=uuid.uuid4().hex[:12]).scan()
    outputs = write_reports(result, args.output, formats)
    counts = result.risk_counts
    print(
        f"扫描完成：文件 {result.files_scanned}/{result.files_total}，"
        f"命中 {len(result.findings)} 项 "
        f"(高危 {counts['high']} / 中危 {counts['medium']} / 低危 {counts['low']})"
    )
    for warning in result.warnings:
        print(f"[告警] {warning}", file=sys.stderr)
    for report_format, path in outputs.items():
        print(f"{report_format.upper()} 报告：{path}")
    return 0


def _run_web(args: argparse.Namespace) -> int:
    try:
        address = ipaddress.ip_address(args.host)
    except ValueError as exc:
        raise ValueError("host 必须为环回 IP 地址") from exc
    if not address.is_loopback:
        raise ValueError("安全限制：Web 服务仅允许监听 127.0.0.1 或 ::1")
    if not 1 <= args.port <= 65535:
        raise ValueError("port 必须在 1-65535 之间")
    from firm_audit.web import create_app

    app = create_app()
    print(f"{TOOL_NAME} Web 服务：http://127.0.0.1:{args.port}")
    app.run(host="127.0.0.1", port=args.port, debug=False, use_reloader=False)
    return 0


def _run_cleanup(args: argparse.Namespace) -> int:
    if not args.yes:
        print("清理会删除本地任务元数据与报告，请追加 --yes 确认。", file=sys.stderr)
        return 2
    removed = cleanup_data()
    print("本地数据已清理。" if removed else "未发现需要清理的数据。")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return _run_scan(args)
        if args.command == "web":
            return _run_web(args)
        if args.command == "cleanup":
            return _run_cleanup(args)
    except (PathValidationError, ValueError, OSError) as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
