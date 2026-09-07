---
name: jingl-analyzer
description: 对 Java、Spring Boot、Jalor 代码仓进行 18 类安全分析；先发现并分级，再按漏洞目标选择验证，输出有证据边界的报告。
trigger_keywords: [JingL, 漏洞分析, 漏洞扫描, 扫描漏洞, 安全扫描, 代码扫描, 分析漏洞]
skill_version: 2.0.0
rules_version: 2.0.0
---

# JingL 安全分析

用户说“jingl 扫描 <代码仓或汇总根目录>”时使用。仅分析用户指定范围；正式覆盖 Java / Spring Boot / Jalor，关联前端或其他语言时明确实际覆盖能力。版本和报告契约均为 2.0.0。

## 核心执行约束

- 先扫描、去重和初步分级，后深审与选择验证；不为每个关键词命中生成 POC。
- P0–P3 同时表达严重度和处理紧迫度。初评与终评保留变化理由；P3 不表示误报，未执行不表示低风险。
- 必须区分源码判断、局部模拟和真实目标行为。模型解释、复制的漏洞逻辑、模拟返回值都不能充当目标执行证据。
- 按漏洞目标决定验证深度，不按固定 Controller/Service/DAO 层数判断完整性。
- 没读到防护实现、运行配置或业务权限政策时明确缺口；既不能自动确认，也不能自动排除。
- 支持当前平台提供的文件、搜索、终端和测试工具；不要求新建扫描平台、常驻服务或多 Agent 系统。

## 按需读取

启动只读本入口、`shared-references/source-routing.md`、`shared-references/scan-index.md`、`shared-references/candidate-ranking.md`。同一运行内不重复加载未变文件。

| 触发点 | 读取文件 |
|---|---|
| 建立范围及统计 | `shared-references/coverage-metrics.md` |
| 发现服务、消息或共享存储边界（单仓也检查） | `shared-references/repo-boundary-manifest.md` |
| 开始深审 | `shared-references/proof-schema.md`、`shared-references/subskill-contract.md`，只加载命中类型的 `skill/<类型>/skill.md` |
| 审查防护或证明义务 | `shared-references/sanitizers.md`、`shared-references/proof-patterns.md` 的对应条目 |
| 追踪尚未闭合的链路 | `shared-references/call-chain-tracing.md`；跨仓再读 `shared-references/cross-repo-tracing.md` |
| 候选通过验证准入 | `shared-references/poc-generation.md`、`shared-references/poc-execution.md` |
| 验证需要 HTTP 入口 | `shared-references/http-extraction.md` |
| 验证目标涉及真实传输行为 | `shared-references/security-tool-probing.md` |
| 平台支持且用户授权并行 | `shared-references/agent-output-schema.md`；无并行也能完成全部流程 |
| 生成报告 | `shared-references/report-schema.md` |
| 维护规则 | `shared-references/regression-matrix.md`，扫描时不加载回归材料 |

工具不能按段读取时可整份读取相应引用，但记录实际读取量，不宣称只消耗对应条目的 token。

## 工作流

1. **范围与画像。** 记录仓库版本、构建模块、输入源、实际安全链、配置优先级及预算；建立跨仓边界索引。不要运行构建来代替画像。
2. **候选发现。** 按索引批量搜索，再读命中上下文；结构、配置、数据流检查补充关键词。搜索截断必须分片重试或明确未覆盖。保存位置和摘要，不把整仓内容送入每次推理。
3. **去重与初评。** 同根因、同路径防护合并，保留受影响入口；分别记录初评 P0–P3 和证据缺口。P0/P1 优先深审；P2/P3 保留清单。高后果且不确定的项不得仅因证据少而压入低级。
4. **类型深审与全局关联。** 读取必要子 Skill，追踪真实实现、安全拦截器、配置、依赖和跨仓边界；合并新的等价路径，避免重复测试。补充事实可随时调整分级。未审项标“待审查”，不得消失。
5. **确定证明目标。** 先记录要证明的安全属性、最小真实目标、可观察结果及对照，再判断是否值得验证。默认先给出源码结果；具有价值且环境/授权具备的候选进入模拟或集成验证。源码足以支持的发现可保留“源码确认”，不强制为凑 POC 运行测试。
6. **选择执行。** 复用项目原有构建、测试和依赖；同模块共用验证环境。只替换不承担待证安全逻辑的外部依赖。缺环境、构建失败、运行超时分别记录；有新证据才修正或重试，默认最多两次修复重试。失败不转误报，也不无限扩建环境。
7. **审定与报告。** 按 proof-schema 审查证据和可宣称影响，生成完整结构化结果及四个报告视图。运行报告校验；统计遗漏、未验证原因和实际耗时/token。确认问题后给出针对真实实现的修复方向，不自动修改被扫描业务代码。

## 预算与增量

用户给定预算优先；无预算时不虚构半小时硬截止。按阶段记录时间，模型 token 不可得则为 null。预算不足先完成高危深审并保留全部未完成候选及接力信息，不把部分扫描称为全量完成。

复用键至少包含目标提交/文件内容摘要、规则版本、运行配置、依赖版本和验证目标。跨入口防护不同不可共用结论；文件变化必须沿调用关系使受影响证据失效。跨运行缓存是可选优化，不为首次扫描搭建缓存服务。
