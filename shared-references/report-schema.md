# 报告契约 2.0.0

结构化 JSON 为唯一数据源，四个原有 Sheet 名称保留；表格渲染不可修改结论。不能生成 XLSX 的平台输出同名 Markdown/CSV 视图并说明，不能声称已生成工作簿。

## 顶层字段

`schema_version` 为 2.0.0；`skill_version`、`rules_version` 记录实际使用版本，当前均为 2.0.1；`run_id`、`repositories`（repo_id/revision/path）、`findings`、`transport_links`、`cross_repo_chains`、`metrics`、`limitations`。`metrics.candidates`、`reviewed`、`pending_review` 必须与发现记录一致。

## 每条 finding 的必需字段

| 字段 | 规则 |
|---|---|
| id / repo_id / location / type | 唯一编号、已登记仓库、真实源码位置、18 类之一 |
| initial_priority / priority | P0/P1/P2/P3 或 null；沿用现有严重度兼紧迫度 |
| grade_provisional / grade_basis | 布尔值及非空依据；null 级别必须待定 |
| status / source_closed | 按 proof-schema.md；待审查不得源码闭合 |
| evidence | 八维对象，各含 state、summary、refs；observed 需非空证据引用 |
| validation | 见下表；未执行也必须明确 NOT_RUN/SKIPPED/BLOCKED 和原因 |
| trigger / exploitation / reason / remediation | 触发条件、证明范围内的利用方式、根因、修复；未能确定时写具体缺口 |
| missing / related_findings | 缺口字符串列表及关联编号列表，无则空列表 |

## validation

`status`、`scope`、`goal`、`reason`、`target_executed`、`controls_passed`、`result_supported`、`command`、`environment`、`exit_code`、`executed_at`、`artifacts`。

前三个布尔标记需依据原始结果，不可作为人工绕过确认门槛的开关。artifacts 为对象列表，每项 path（相对报告根目录）、sha256（实际文件摘要）。确认至少一项实际原始证据；文件不存在/摘要不符拒绝交付。PASSED 必须 exit_code=0 且目标、对照和结果检查均通过；其他状态的 result_supported 必须为 false。失败尝试也保留命令、环境和证据，缺失说明原因。

## 四个视图

1. **漏洞扫描报告**：全部候选可追溯；默认显示确认、源码确认、高危待审查/待验证/缺源码，单列未审项计数。包含级别（暂定标记）、结论、验证状态/范围、位置、触发、利用、根因、修复和证据引用。误报另筛选显示，不删除。
2. **传输链路探测分析**：transport_links，注明源码/工具依据，未执行留空工具而非编造。
3. **扫描统计**：范围、各结论数量、覆盖缺口、耗时/token（不可得为 null）、构建/重试、局限性。
4. **跨代码仓调用链分析**：cross_repo_chains，逐边证据、关联发现、未知边界和验证范围。无链写未发现关联及覆盖限制。

## 1.1.0 兼容

旧报告原样保留；不静默重写为 2.0.0。旧 `severity` 中文展示字段若存在继续留作 legacy_severity；新输出 priority 为权威，展示映射 P0=严重、P1=高、P2=中、P3=低。旧 priority 曾仅用于排队，导入必须按实际影响重评并保存 original_priority，不直接当新严重度。

旧“确认”无原始执行证据时最多迁为“源码确认”，源码证据不足则待验证；旧“缺失关键源码”按真实缺口重新分类。历史报告导入不由校验器自动完成，需显式适配，未适配版本拒绝当新报告读取。

交付前运行 `python scripts/validate-report.py <report.json> --evidence-root <报告根目录>`。校验器检查格式、状态组合、引用和文件摘要；不能代替人工核对漏洞逻辑、真实目标及对照质量。
