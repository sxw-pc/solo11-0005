/* 本地交互脚本：任务提交与进度轮询，不访问任何外部资源。 */
(function () {
  "use strict";
  function setText(id, value) { var node = document.getElementById(id); if (node) { node.textContent = value; } }
  function installForm() {
    var form = document.getElementById("scan-form");
    if (!form) { return; }
    form.addEventListener("submit", function (event) { event.preventDefault(); submitScan(form, false); });
  }
  async function submitScan(form, confirmed) {
    var button = document.getElementById("scan-submit"), errorBox = document.getElementById("form-error");
    var fields = form.elements;
    errorBox.textContent = "";
    var formats = Array.from(form.querySelectorAll('input[name="formats"]:checked')).map(function (item) { return item.value; });
    var payload = {
      target: fields.target.value.trim(), rules_dir: fields.rules_dir.value.trim() || null,
      max_size_mb: Number(fields.max_size_mb.value), max_depth: Number(fields.max_depth.value),
      formats: formats, extract_archives: fields.extract_archives.checked,
      confirmed: confirmed || fields.confirmed.checked
    };
    if (!payload.target) { errorBox.textContent = "请填写扫描目标路径。"; return; }
    if (!formats.length) { errorBox.textContent = "请至少选择一种报告格式。"; return; }
    button.disabled = true; button.textContent = "任务提交中…";
    try {
      var response = await fetch(form.dataset.endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
      var data = await response.json();
      if (response.status === 409 && data.code === "confirmation_required") {
        var stats = data.survey || {};
        var prompt = "目标包含 " + (stats.files || 0) + " 个文件，共 " + (stats.bytes || 0) + " 字节，超过确认阈值。确认继续扫描？";
        if (window.confirm(prompt)) { return submitScan(form, true); }
        errorBox.textContent = "已取消大目录扫描。"; return;
      }
      if (!response.ok) { throw new Error(data.error || "任务提交失败"); }
      window.location.href = data.page_url;
    } catch (error) { errorBox.textContent = error.message || "网络请求失败"; }
    finally { button.disabled = false; button.textContent = "开始离线扫描"; }
  }
  function installPolling() {
    var panel = document.querySelector("[data-task-poll]");
    if (!panel) { return; }
    var taskId = panel.dataset.taskPoll, timer = null;
    var labels = { pending: "等待中", running: "扫描中", completed: "已完成", failed: "失败" };
    async function tick() {
      try {
        var response = await fetch("/api/tasks/" + encodeURIComponent(taskId), { cache: "no-store" });
        var data = await response.json();
        if (!response.ok) { throw new Error(data.error || "进度查询失败"); }
        var percent = Math.max(0, Math.min(100, Number(data.progress) || 0));
        setText("progress-percent", percent + "%"); setText("phase-text", data.phase || labels[data.status] || "处理中");
        setText("files-processed", data.files_processed); setText("files-total", data.files_total);
        setText("findings-count", data.findings_count); setText("task-status", labels[data.status] || data.status);
        setText("current-file", data.current_file || "正在准备下一个文件…");
        var bar = document.getElementById("progress-bar");
        if (bar) { bar.style.width = percent + "%"; bar.parentElement.setAttribute("aria-valuenow", String(percent)); }
        if (data.status === "completed") {
          window.setTimeout(function () { window.location.href = "/tasks/" + encodeURIComponent(taskId) + "/result"; }, 450); return;
        }
        if (data.status === "failed") {
          document.getElementById("progress-error").textContent = "扫描失败：" + (data.error || "未知错误");
          document.getElementById("progress-error").style.color = "#b42318"; return;
        }
        timer = window.setTimeout(tick, 1000);
      } catch (error) { setText("phase-text", "进度连接中断，正在重试…"); timer = window.setTimeout(tick, 2500); }
    }
    tick();
    window.addEventListener("pagehide", function () { if (timer) { window.clearTimeout(timer); } });
  }
  document.addEventListener("DOMContentLoaded", function () { installForm(); installPolling(); });
}());
