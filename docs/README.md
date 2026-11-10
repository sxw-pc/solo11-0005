# 固漏巡检仪（firm_audit）

> **合规提示**：仅允许用于自有或已取得书面授权的固件安全测试。禁止用于未授权设备、系统或网络；使用者自行承担全部法律责任。

纯离线、只读的 IoT 固件**文件系统静态安全巡检工具**。输入必须是已解压固件目录；不解包镜像、不仿真、不联网、不利用漏洞、不上传数据。内置规则、测试样例、样式与脚本全部本地化。

## 功能

- 递归盘点并过滤符号链接、超大文件、图片/音视频与压缩包，可选安全解包扫描。
- 硬编码凭证：内置 130+ 弱口令/密钥特征，证据强制打码。
- 敏感文件：账户、密钥、备份、日志、证书、数据库、命令历史等 8 类。
- 不安全配置：SSH、Telnet、FTP、防火墙与 Web 共 28 条规则。
- 遗留调试接口：测试账户、adb/调试开关、串口控制台、后门脚本、调试页面等 12 条。
- 本地 Web：仅监听 127.0.0.1，异步任务、进度轮询、最近 10 次历史。
- 报告：JSON、Markdown、自包含 HTML，含元数据、统计、证据、位置与修复建议。
- 防护：路径/符号链接/系统目录拦截、Zip Slip/压缩炸弹防护、临时清理、凭证打码、CSP 与同源校验。

## 快速开始

```bash
python -m pip install -r requirements.txt
python -m firm_audit web --port 8080
python -m firm_audit scan --target ./tests/fixtures/mock_firmware --output ./report
python -m pytest tests/ -v
```

Web 地址 `http://127.0.0.1:8080`。目标超过 5000 个文件或 512 MiB 需追加 `--yes` 确认。

## 安全与数据

任务数据位于 `~/.firm_audit`，用 `python -m firm_audit cleanup --yes` 清理。扫描只读；解包仅在临时目录并自动删除；报告中口令、密钥、Token 等仅保留首尾各 2 位；无 CDN、远程字体或外发请求。

## 文档与限制

`docs/usage.md`（命令/Web/报告）、`rule_dev_guide.md`（规则扩展）、`legal_notice.md`（授权与免责）、`changelog.md`（版本）。静态检测可能误报或漏报，不能替代人工复核；加密/专有格式可能无法识别，工具不判断可利用性。
