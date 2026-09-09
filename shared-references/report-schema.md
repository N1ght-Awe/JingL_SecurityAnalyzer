# 报告契约 2.1.0

结构化 JSON 为唯一数据源，四个原有 Sheet 名称保留；表格渲染不可修改结论。不能生成 XLSX 的平台输出同名 Markdown/CSV 视图并说明，不能声称已生成工作簿。

## 顶层字段

新报告 `schema_version`、`skill_version`、`rules_version` 为 2.1.0；`run_id`、`repositories`（repo_id/revision/path）、`findings`、`transport_links`、`cross_repo_chains`、`metrics`、`limitations` 继续使用。`metrics.candidates`、`reviewed`、`pending_review` 必须与 findings 一致，不混入控制侧观察。

2.1.0 另要求 `scan_types`（非空18类子集）、`assets`、`coverage`、`coverage_status`，具体结构与含义见 coverage-metrics.md 和 repo-boundary-manifest.md；以及 `control_knowledge`、`control_applications`、`control_observations` 三个数组（无记录填空数组），结构见 control-knowledge.md、protection-audit-methodology.md。完整范围或部分报告均可交付，不把覆盖状态与 finding/validation 状态混为一谈。

路径复用的实现指纹是仓库相对 path 与真实 sha256；与 validation.artifacts（报告根目录内的运行证据）用途不同。报告校验器检查前者结构与引用，不自动读取业务仓，不宣称重新计算了源码摘要或验证了适用性。

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

1. **漏洞扫描报告**：全部候选可追溯；默认显示确认、源码确认、高危待审查/待验证/缺源码，单列未审项计数。包含级别（暂定标记）、结论、验证状态/范围、位置、触发、利用、根因、修复和证据引用。误报另筛选显示，不删除。控制侧观察在本视图独立附表呈现，标明 control_gap/improvement、证据边界和关联 finding，不混入漏洞数量或新建第五个必需视图。
2. **传输链路探测分析**：transport_links，注明源码/工具依据，未执行留空工具而非编造。
3. **扫描统计**：范围、各结论数量、逐类型必需/已审资产、coverage_status 与 gaps、耗时/token（不可得为 null）、构建/重试、局限性。防护知识和控制观察数单列；partial 时明确仅完成哪些范围，不输出全局阴性结论。
4. **跨代码仓调用链分析**：cross_repo_chains，逐边证据、关联发现、未知边界和验证范围。无链写未发现关联及覆盖限制。

## 历史兼容与字段边界

校验器继续接受 skill/rules 2.0.0/2.0.1 的 schema 2.0.0 报告，维持原证据门槛；这只表示历史契约合格，不能宣称完成2.1覆盖/复用检查。2.1.0规则新产出必须用2.1.0契约。历史报告不可仅改版本号，需实际补齐资产与覆盖证据；无法补齐时保留历史原件或如实迁移为partial，禁止补造已审资产。

新功能字段放在2.0报告中会拒绝，避免被默默忽略。旧 `poc_validation_mode`、`report_validation_mode`、`exploitation_method`、finding.http_interface/http_poc 不作为新契约使用；HTTP材料写 exploitation/外部附件，执行情况用 validation。不强制七章节报告，不把 HTTP 推导当成运行模式或通过证据。

## 1.1.0 兼容

旧报告原样保留；不静默重写为当前契约。旧 `severity` 中文展示字段若存在继续留作 legacy_severity；新输出 priority 为权威，展示映射 P0=严重、P1=高、P2=中、P3=低。旧 priority 曾仅用于排队，导入必须按实际影响重评并保存 original_priority，不直接当新严重度。

旧“确认”无原始执行证据时最多迁为“源码确认”，源码证据不足则待验证；旧“缺失关键源码”按真实缺口重新分类。历史报告导入不由校验器自动完成，需显式适配，未适配版本拒绝当新报告读取。

交付前运行 `python scripts/validate-report.py <report.json> --evidence-root <报告根目录>`。校验器检查格式、状态组合、引用和文件摘要；不能代替人工核对漏洞逻辑、真实目标及对照质量。
