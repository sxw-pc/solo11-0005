"""本地 Flask Web 应用初始化，仅面向单用户环回访问。"""

from __future__ import annotations

import os
from urllib.parse import urlparse

from flask import Flask, jsonify, request

from firm_audit import DISCLAIMER, TOOL_NAME, __version__
from firm_audit.core.task_manager import TaskManager

ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}


def create_app(
    test_config: dict | None = None, manager: TaskManager | None = None
) -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.urandom(32),
        MAX_CONTENT_LENGTH=64 * 1024,
        JSON_SORT_KEYS=False,
        TOOL_NAME=TOOL_NAME,
        VERSION=__version__,
        DISCLAIMER=DISCLAIMER,
    )
    if test_config:
        app.config.update(test_config)
    app.json.ensure_ascii = False
    app.extensions["task_manager"] = manager or TaskManager()
    _install_security_hooks(app)

    from .routes import bp

    app.register_blueprint(bp)

    @app.errorhandler(404)
    def not_found(_error):
        if request.path.startswith("/api/"):
            return jsonify({"error": "接口不存在"}), 404
        return (
            "<h1>404</h1><p>请求的页面不存在。</p>" "<p><a href='/'>返回首页</a></p>",
            404,
        )

    @app.errorhandler(413)
    def too_large(_error):
        return jsonify({"error": "请求体过大"}), 413

    return app


def _install_security_hooks(app: Flask) -> None:
    @app.before_request
    def check_host() -> tuple | None:
        host = (request.host or "").lower()
        hostname = (
            host.split("]")[0] + "]" if host.startswith("[") else host.split(":")[0]
        )
        if hostname not in ALLOWED_HOSTS:
            return jsonify({"error": "仅允许通过本地环回地址访问"}), 403
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            origin = request.headers.get("Origin")
            if origin:
                parsed = urlparse(origin)
                if f"{parsed.scheme}://{parsed.netloc}" != request.host_url.rstrip("/"):
                    return jsonify({"error": "拒绝跨站请求"}), 403
        return None

    @app.after_request
    def security_headers(response):
        script_src = "'self'"
        if (
            request.endpoint == "main.download_report"
            and (request.view_args or {}).get("report_format") == "html"
        ):
            script_src = "'unsafe-inline'"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline'; "
            f"script-src {script_src}; object-src 'none'; "
            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=()"
        )
        return response
