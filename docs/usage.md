# 使用说明

## 安装

要求 Python 3.10–3.12。把全部 wheel 放入本地目录后离线安装：

```bash
python -m pip install --no-index --find-links ./offline_wheels -r requirements.txt
```

程序不访问网络，Web 服务只绑定环回地址。

## 命令行

```bash
python -m firm_audit scan --target /path/to/extracted_firmware --output ./report \
  --rules-dir ./custom_rules --formats json,md,html --max-size-mb 100 --max-depth 15
```

- `--target` 必填，已解压目录或单个文件；`--output` 报告目录，默认 `./report`。
- `--rules-dir` 追加自定义 YAML 规则，重复 ID 保留先加载项；`--formats` 为 `json,md,html`。
- `--max-size-mb` 单文件阈值 1–2048，`--max-depth` 1–64，`--extract-archives` 安全解包 zip/tar。
- `--yes`：目标超过 5000 个文件或 512 MiB 时确认继续。

退出码 `0` 成功，`2` 参数/路径/运行错误。扫描不会修改输入文件。

## Web

```bash
python -m firm_audit web --port 8080
```

仅允许 `--host 127.0.0.1` 或 `::1`。页面填写本机可访问的已解压目录；一次只运行一个任务；首页保留最近 10 条任务元数据。完成后查看脱敏详情并下载报告。请勿通过反向代理暴露到非环回网络。

安全机制：Host 白名单、写请求同源校验、CSP、`X-Frame-Options: DENY`、请求体限制、任务 ID 校验。

## 报告

- JSON：含 schema/工具版本、扫描元数据、文件统计、风险统计、逐条结果与告警。
- Markdown：便于审阅归档，证据折叠。
- HTML：单文件自包含，无外部资源，可离线打印。

报告包含合规提示、风险等级、分类统计、路径、行号/二进制偏移、脱敏证据、描述与修复建议。不会出现明文口令、哈希、私钥或 Token。

## 数据与清理

报告、历史与临时文件位于 `~/.firm_audit`（测试可用 `FIRM_AUDIT_HOME` 覆盖）。清理：

```bash
python -m firm_audit cleanup --yes
```

未加 `--yes` 不删除；运行中的任务不可清理。

## 常见问题

- 路径被拒：确认目标为普通已解压目录，不含 `..`、符号链接或系统关键目录。
- 文件被跳过：查看 `skipped_details`，常见原因为符号链接、大小/深度限制、媒体/压缩包或读取失败。
- 缺少预期命中：核对规则路径、文件类型与编码，可用自定义规则验证特征。
- Web 403：使用了非环回 Host 或跨站 Origin，请通过 `127.0.0.1` 访问；测试全部离线运行。
