"""Web 页面与 JSON 接口路由。"""

from __future__ import annotations

from pathlib import Path

from flask import (
    Blueprint,
    abort,
    current_app,
    jsonify,
    render_template,
    request,
    send_file,
)

from firm_audit.core.file_filter import survey
from firm_audit.core.path_validator import PathValidationError, validate_target
from firm_audit.core.task_manager import TaskBusyError, TaskManager
from firm_audit.models.task import ScanOptions
from firm_audit.report import build_report_data

bp = Blueprint("main", __name__)
MAX_SURVEY_FILES = 5000
MAX_SURVEY_BYTES = 512 * 1024 * 1024
STATUS_LABELS = {
    "pending": "等待中",
    "running": "扫描中",
    "completed": "已完成",
    "failed": "失败",
}


def _manager() -> TaskManager:
    return current_app.extensions["task_manager"]


def _error(message: str, status: int, code: str | None = None):
    payload = {"error": message}
    if code:
        payload["code"] = code
    return jsonify(payload), status


def _example_target() -> str:
    root = Path(__file__).resolve().parent.parent.parent
    candidate = root / "tests" / "fixtures" / "mock_firmware"
    return str(candidate) if candidate.is_dir() else ""


def _history_view(entry: dict) -> dict:
    item = dict(entry)
    if not isinstance(item.get("options"), dict):
        item["options"] = {"target": item.get("target", "")}
    if "findings_count" not in item:
        item["findings_count"] = (item.get("counts") or {}).get("total", 0)
    if not isinstance(item.get("reports"), dict):
        item["reports"] = item.get("report_paths") or {}
    item["status_label"] = STATUS_LABELS.get(item.get("status"), "未知")
    return item


@bp.get("/")
def index():
    tasks = [_history_view(item) for item in _manager().list_tasks()]
    return render_template(
        "index.html",
        tasks=tasks,
        example_target=_example_target(),
    )


@bp.get("/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "tool": current_app.config["TOOL_NAME"],
            "version": current_app.config["VERSION"],
            "offline": True,
        }
    )


@bp.post("/api/tasks")
def create_task():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return _error("请求必须为 JSON 对象", 400)
    payload.pop("output_dir", None)
    try:
        options = ScanOptions.from_mapping(payload)
        if not options.target:
            raise ValueError("扫描目标不能为空")
        resolved = validate_target(options.target)
        stats = survey(resolved, options.max_depth)
        if (
            stats["files"] > MAX_SURVEY_FILES or stats["bytes"] > MAX_SURVEY_BYTES
        ) and not payload.get("confirmed"):
            return (
                jsonify(
                    {
                        "error": "目标文件数量或体积超过阈值，请确认后继续",
                        "code": "confirmation_required",
                        "survey": stats,
                    }
                ),
                409,
            )
        task = _manager().submit(options)
    except PathValidationError as exc:
        return _error(str(exc), 400, "invalid_path")
    except TaskBusyError as exc:
        return _error(str(exc), 409, "task_busy")
    except (ValueError, TypeError) as exc:
        return _error(f"参数错误: {exc}", 400, "invalid_parameter")
    return (
        jsonify(
            {
                "task": task.public(),
                "progress_url": f"/api/tasks/{task.task_id}",
                "page_url": f"/tasks/{task.task_id}",
            }
        ),
        202,
    )


@bp.get("/api/tasks/<task_id>")
def task_status(task_id: str):
    task = _manager().get(task_id)
    if task is None:
        return _error("任务不存在", 404)
    return jsonify(task.public())


@bp.get("/tasks/<task_id>")
def task_progress(task_id: str):
    task = _manager().get(task_id)
    if task is None:
        abort(404)
    return render_template("task_progress.html", task=task.public())


@bp.get("/tasks/<task_id>/result")
def task_result(task_id: str):
    task = _manager().get(task_id)
    report = None
    if task is not None and task.result is not None:
        report = build_report_data(task.result)
    else:
        report = _manager().load_report(task_id, "json")
    if report is None:
        abort(404)
    return render_template(
        "result.html",
        task=task.public() if task else None,
        report=report,
        status_labels=STATUS_LABELS,
    )


@bp.get("/tasks/<task_id>/report/<report_format>")
def download_report(task_id: str, report_format: str):
    path = _manager().report_path(task_id, report_format)
    if path is None:
        abort(404)
    mimetype = {
        "json": "application/json",
        "md": "text/markdown",
        "html": "text/html",
    }[report_format]
    attachment = report_format != "html" or request.args.get("download") == "1"
    return send_file(
        path,
        mimetype=mimetype,
        as_attachment=attachment,
        download_name=path.name,
        max_age=0,
    )
