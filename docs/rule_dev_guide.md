# 规则开发指南

## 结构

规则为 UTF-8 YAML，内置目录 `firm_audit/rules/`，自定义目录通过 `--rules-dir` 追加。单文件不超过 1 MiB，最多加载 2000 条。每个文件含 `version`、`category` 与 `rules` 列表。

```yaml
version: "1.0.0"
category: insecure_config
rules:
  - id: CUSTOM-001
    title: 示例配置风险
    severity: high
    scene: 示例服务
    match_type: regex
    pattern: '(?i)^\s*unsafe_option\s+on\s*$'
    paths: ["**/app.conf"]
    file_types: [text]
    tags: [example]
    description: 开启不安全选项会降低设备防护能力。
    remediation: 关闭该选项并复核配置基线。
```

## 字段

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `id` | 是 | 大写字母开头，仅字母/数字/`_`/`-`，长度 3–64，全局唯一 |
| `title` | 否 | 展示标题，缺省使用 ID |
| `category` | 是 | `hardcode_cred`、`sensitive_file`、`insecure_config`、`debug_interface` |
| `severity` | 是 | `high`/`medium`/`low`，兼容中文别名 |
| `scene` | 是 | 适用场景 |
| `match_type` | 是 | `exact`、`regex`、`permission`、`hash`、`path` |
| `pattern` | 是 | 字符串或列表，含义由匹配类型决定 |
| `paths` | 否 | 相对路径 glob，限定非 `path` 规则范围 |
| `file_types` | 否 | `text`、`binary` 或 `any` |
| `mask` | 否 | 强制对证据兜底打码 |
| `tags` | 否 | 标签列表，检测器用于补充元数据 |
| `metadata` | 否 | 附加说明映射 |
| `description` | 是 | 风险说明 |
| `remediation` | 是 | 修复建议 |
| `enabled` | 否 | 默认 `true` |

## 匹配类型

- `exact`：任一 pattern 作为子串出现在一行或二进制可打印字符串中。
- `regex`：逐行 Python 正则；命名组 `secret`、`password`、`passwd`、`token`、`value` 指定打码内容。
- `permission`：`world_writable`、`world_readable`、`any_world` 或八进制模式（如 `0644`）。
- `hash`：64 位 SHA-256，精确比较文件摘要。
- `path`：按相对路径 glob 命中，不读取内容。

路径同时匹配完整相对路径、以 `/` 开头的路径和文件名，例如 `**/shadow` 命中 `etc/shadow`。

## 安全约束

- 正则不超过 4000 字符，含高风险嵌套量词会被拒绝；使用锚点和明确字符集避免灾难性回溯。
- 凭证规则须设置 `mask: true` 或命名捕获组，报告层仍会二次脱敏；规则不得含真实厂商、设备、账号、密钥或外部链接。
- 规则只做静态匹配，不执行命令、不发起网络请求。

## 验证

```bash
python -m pytest tests/unit/test_rule_engine.py -v
python -m firm_audit scan --target ./tests/fixtures/mock_firmware --rules-dir ./tests/fixtures/mock_rules --output ./report
```

新增规则应补充命中与未命中样例，核对路径、等级、证据行号与打码结果。加载失败不会中断扫描，告警写入结果 `warnings`。
