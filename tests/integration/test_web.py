"""Flask 本地服务端到端测试。"""

import time

import pytest

from firm_audit.core.task_manager import TaskManager
from firm_audit.web import create_app
from firm_audit.web import routes as routes_module


@pytest.fixture
def client(tmp_path):
    manager = TaskManager(home=tmp_path / ".firm_audit")
    test_client = create_app({"TESTING": True}, manager).test_client()
    test_client.manager = manager
    return test_client


def wait_task(client, task_id, timeout=20.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        payload = client.get(f"/api/tasks/{task_id}").get_json()
        if payload["status"] in {"completed", "failed"}:
            return payload
        time.sleep(0.05)
    raise AssertionError("Web 任务超时")


def test_pages_health_security_headers_and_host_guard(client, firmware_dir):
    home = client.get("/")
    assert home.status_code == 200 and "固漏巡检仪" in home.get_data(as_text=True)
    assert "default-src 'self'" in home.headers["Content-Security-Policy"]
    assert home.headers["X-Frame-Options"] == "DENY"
    assert client.get("/health").get_json() == {"status": "ok", "tool": "固漏巡检仪",
                                                "version": "1.0.0", "offline": True}
    css = client.get("/static/css/bootstrap.min.css")
    assert css.status_code == 200 and b"http://" not in css.data and b"https://" not in css.data
    assert client.get("/api/nope").status_code == 404
    assert client.get("/nope").status_code == 404
    assert client.get("/", environ_overrides={"HTTP_HOST": "evil.example"}).status_code == 403
    payload = {"target": str(firmware_dir)}
    cross = client.post("/api/tasks", json=payload, headers={"Origin": "http://evil"})
    assert cross.status_code == 403
    same = client.post("/api/tasks", json=payload, headers={"Origin": "http://localhost"})
    assert same.status_code == 202
    wait_task(client, same.get_json()["task"]["task_id"])


def test_task_flow_result_and_downloads(client, firmware_dir):
    response = client.post("/api/tasks", json={"target": str(firmware_dir)})
    assert response.status_code == 202
    task_id = response.get_json()["task"]["task_id"]
    done = wait_task(client, task_id)
    assert done["findings_count"] == 12 and done["progress"] == 100
    assert client.get(f"/tasks/{task_id}").status_code == 200
    result = client.get(f"/tasks/{task_id}/result")
    assert result.status_code == 200 and "HCRED-001" in result.get_data(as_text=True)
    assert "Fw-S3cure-2024!" not in result.get_data(as_text=True)
    for report_format in ("json", "md", "html"):
        download = client.get(f"/tasks/{task_id}/report/{report_format}")
        assert download.status_code == 200 and b"Fw-S3cure-2024!" not in download.data
    assert client.get(f"/tasks/{task_id}/report/pdf").status_code == 404
    assert client.get("/tasks/missing/result").status_code == 404


def test_legacy_history_entry_is_renderable(client):
    client.manager._history = [{
        "task_id": "legacy", "status": "completed", "target": "/tmp/fw",
        "created_at": "2026-01-01T00:00:00+00:00", "counts": {"total": 3},
        "report_paths": {},
    }]
    response = client.get("/")
    assert response.status_code == 200 and "/tmp/fw" in response.get_data(as_text=True)


def test_api_validation_confirmation_and_busy(client, firmware_dir, monkeypatch):
    assert client.post("/api/tasks", data="x").status_code == 400
    assert client.post("/api/tasks", json={"target": ""}).status_code == 400
    bad_path = client.post("/api/tasks", json={"target": "Z:/missing/firmware"})
    assert bad_path.status_code == 400 and bad_path.get_json()["code"] == "invalid_path"
    invalid = {"target": str(firmware_dir), "max_depth": 0}
    assert client.post("/api/tasks", json=invalid).status_code == 400
    monkeypatch.setattr(routes_module, "MAX_SURVEY_FILES", 0)
    payload = {"target": str(firmware_dir)}
    pending = client.post("/api/tasks", json=payload)
    assert pending.status_code == 409
    assert pending.get_json()["code"] == "confirmation_required"
    client.manager._active = "occupied"
    busy = client.post("/api/tasks", json={**payload, "confirmed": True})
    assert busy.status_code == 409 and busy.get_json()["code"] == "task_busy"
    client.manager._active = None
    assert client.get("/api/tasks/" + "x" * 64).status_code == 404
    assert client.get("/tasks/" + "x" * 64).status_code == 404
