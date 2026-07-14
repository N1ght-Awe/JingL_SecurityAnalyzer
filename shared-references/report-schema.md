# 报告数据契约

先汇总结构化finding，再渲染Excel；不得直接从自由文本拼装报告。

## Finding最小字段

```yaml
finding_id: F-001
candidate_ids: [MOD-TYPE-001]
status: 确认|误报|缺失关键源码
severity: 严重|高|中|低
confidence: 高|中|低
type: SQL注入
locations: [path/file:line]
evidence: {source: {}, propagation: {}, sink: {}, sanitizer: {}, guard: {}, transport: {}, preconditions: {}, impact: {}}
call_chain: []
cross_repo_chain_ids: []
fix_direction: 简明修复方向
validation_mode: source-only|authorized-tool-assisted
validation_detail: 直接源码证据或工具原始证据位置
secret_display: "sk-111********1111" # 如涉及凭据，仅保存脱敏展示值
```

## 扫描元数据与覆盖统计

每份报告必须先写入以下元数据；数值口径见 `coverage-metrics.md`。

```yaml
scan_metadata:
  skill_version: 1.1.0
  rules_version: 1.1.0
  scan_started_at: ISO-8601
  target_root: 用户提供的根目录
  repositories: [{repo_id: repo-a, path: relative/path, git_commit: commit-or-unavailable}]
  enabled_scope: Java/Spring Boot/Jalor
  validation_mode: source-only|authorized-tool-assisted
coverage:
  repositories_detected: 0
  java_files_total: 0
  java_files_read: 0
  xml_mapper_files_total: 0
  config_files_total: 0
  files_skipped: [{path_or_pattern: generated/**, reason: 生成代码}]
  grep_truncations: [{rule: pattern, initial_count: 0, retry_completed: true}]
  unresolved_boundaries: []
  limitations: []
```

## 渲染规则

- 输出四个Sheet：漏洞扫描报告、传输链路探测分析、扫描统计、跨代码仓调用链分析。
- `status=确认`时所有适用 `evidence` 字段必须为✅闭合；`缺失关键源码`必须包含缺失原因、影响和接力指引。
- 默认报告只输出确认与缺失关键源码；P2/P3只输出类型统计、数量和处理摘要，并明确提示用户可选择导出候选附表。用户选择后才输出P2/P3逐条信息。
- 不在报告中写入完整密钥、令牌、密码或可复用Payload。凭据仅展示前缀和后缀，例如`sk-111********1111`，同时给出文件位置和行号。
