---
name: jingl-analyzer
description: 对 Java、Spring Boot、Jalor 代码仓进行 18 类安全分析；先发现、筛选并分级，再对 P0/P1/P2 按漏洞影响开展深度验证，输出有证据边界的报告。
trigger_keywords: [JingL, 漏洞分析, 漏洞扫描, 扫描漏洞, 安全扫描, 代码扫描, 分析漏洞]
skill_version: 2.3.0
rules_version: 2.3.0
---

# JingL 安全分析

用户说“jingl 扫描 <代码仓或汇总根目录>”时使用。仅分析用户指定范围；正式覆盖 Java / Spring Boot / Jalor，关联前端或其他语言时明确实际覆盖能力。Skill 与规则版本为 2.3.0，新报告契约为 2.3.0，校验器继续接受历史 2.0 / 2.1 / 2.2 契约。

## 核心执行约束

- 危险模式、路径可达、漏洞可利用是不同证明层次；确认前主动寻找同路径反证。源码足够时保留源码确认，真实目标验证通过才给确认；mock 命中和断言数量不能扩大证明范围。
- 完成资产枚举再给覆盖结论。必需资产缺失/未审允许部分报告，禁止声称完整覆盖或给未覆盖范围下阴性结论。
- 已核验防护实现可在本轮即时复用；每条新路径仍检查实际调用、适用参数、使用校验结果、无绕过与后续变换。跨轮先重查实现/依赖/配置指纹，不能缓存“接口永久安全”。

- 先扫描、去重、筛选和分级；筛选出的 P0、P1、P2 进入深度验证，不对所有疑似漏洞点全面展开模拟，也不再以“高价值”进行额外筛选。验证深度由漏洞影响及其证明目标决定。
- P0–P3 同时表达严重度和处理紧迫度。初评与终评保留变化理由；P3 不表示误报，未执行不表示低风险。
- 必须区分源码判断、局部模拟和真实目标行为。模型解释、复制的漏洞逻辑、模拟返回值都不能充当目标执行证据。
- 按漏洞影响及其证明目标决定验证深度，不按固定 Controller/Service/DAO 层数判断完整性。
- 没读到防护实现、运行配置或业务权限政策时明确缺口；既不能自动确认，也不能自动排除。
- 候选链路优先用平台已有的符号定义、调用者/被调用者及具体实现查询定位，AST和文本搜索补查结构、配置及动态绑定；关键实现须实际读取。审定前监督原始搜索/读取记录，遗漏防护则定向补查；未闭合不得输出源码确认、确认或误报。
- 支持当前平台提供的文件、搜索、终端和测试工具；不要求新建扫描平台、常驻服务或多 Agent 系统。

## 按需读取

启动只读本入口、`shared-references/source-routing.md`、`shared-references/scan-index.md`、`shared-references/candidate-ranking.md`。同一运行内不重复加载未变文件。

| 触发点 | 读取文件 |
|---|---|
| 建立范围、威胁概览及统计 | `shared-references/threat-model.md`、`shared-references/coverage-metrics.md` |
| 发现服务、消息或共享存储边界（单仓也检查） | `shared-references/repo-boundary-manifest.md` |
| 开始深审 | `shared-references/proof-schema.md`、`shared-references/subskill-contract.md`，只加载命中类型的 `skill/<类型>/skill.md` |
| 首次核验或复用防护函数 | `shared-references/control-knowledge.md` |
| 由控制组件发现覆盖/激活异常 | `shared-references/protection-audit-methodology.md` |
| 整理验证证据与对照 | `shared-references/verification-patterns.md` |
| HTTP 绑定或 Jalor 路由细节需要展开 | `shared-references/http-poc-extraction.md` |
| 审查防护或证明义务 | `shared-references/sanitizers.md`、`shared-references/proof-patterns.md` 的对应条目 |
| 追踪尚未闭合的链路 | `shared-references/call-chain-tracing.md`；跨仓再读 `shared-references/cross-repo-tracing.md` |
| 候选通过验证准入 | `shared-references/poc-generation.md`、`shared-references/poc-execution.md` |
| 验证需要 HTTP 入口 | `shared-references/http-extraction.md` |
| 验证目标涉及真实传输行为 | `shared-references/security-tool-probing.md` |
| 平台支持且用户授权并行 | `shared-references/agent-output-schema.md`；无并行也能完成全部流程 |
| 深审收集回执及审定前监督 | `shared-references/execution-supervision.md` |
| 生成报告 | `shared-references/report-schema.md` |
| 维护规则 | `shared-references/regression-matrix.md`，扫描时不加载回归材料 |

工具不能按段读取时可整份读取相应引用，但记录实际读取量，不宣称只消耗对应条目的 token。

## 工作流

1. **范围与画像。** 记录仓库版本、构建模块、输入源、实际安全链、配置优先级；建立跨仓边界索引，并按 threat-model.md 将系统用途、主体、实际保护边界与待核实条件整理为同一份简短概览，指导后续检查。不要运行构建来代替画像。
2. **候选发现。** 按索引发现候选，再优先用可用语义导航读取定义和调用关系，AST与文本搜索补充定位，再读命中上下文；结构、配置、数据流检查补充关键词。搜索截断必须分片重试或明确未覆盖。发现即按 candidate-ranking 保存候选调用实例与原始证据，再筛选审查，不把整仓内容送入每次推理。
3. **去重与初评。** 同一实例重复命中沿用ID；同根因的不同调用实例关联但分别保留结论；分别记录初评 P0–P3 和证据缺口。筛选出的 P0/P1/P2 均进入深审与深度验证，按严重度安排顺序；P3 保留清单，不默认进入深度验证。高后果且不确定的项不得仅因证据少而压入低级。
4. **类型深审与全局关联。** 按 call-chain-tracing 与 execution-supervision 保存链路工作清单和实际读取回执。读取必要子 Skill，追踪真实实现、安全拦截器、配置、依赖和跨仓边界；复用等价实现分析，逐实例核查防护适用性，避免重复执行同一证明目标。补充事实可随时调整分级。未审项标“待审查”，不得消失。
5. **确定证明目标。** 对筛选出的 P0/P1/P2，依据漏洞影响确定要证明的安全属性、所需真实链路、可观察结果及对照。影响涉及文件操作、权限链或跨仓行为时，验证覆盖相应层次，不统一全面展开。仅当源码足以证明该影响时可保留“源码确认”；需要运行证据但环境或授权不具备时，保留验证任务及阻塞原因，不因条件不足将其筛掉。
6. **选择执行。** 默认选择最小充分的真实验证，不要求所有类型启动全站或发 HTTP。如证明目标必须依赖整套系统、外部服务或端到端环境，先列目标、缺口、启动范围、数据和影响，让用户选择是否启动；已有覆盖该范围的明确授权则继续，不重复询问。未选择启动时保留源码结论、原级别与 BLOCKED 验证计划。 复用项目原有构建、测试和依赖；同模块共用验证环境。只替换不承担待证安全逻辑的外部依赖。缺环境、构建失败、运行超时分别记录；有新证据才修正或重试，默认最多两次修复重试。失败不转误报，也不无限扩建环境。
7. **审定与报告。** 按 execution-supervision 先保存源码侧防护观察，再对照主审结论，明确实际复核上下文；默认最多两轮定向补查，无进展停止，未解决项保留缺口。核对原始候选账本，按 proof-schema 审查每个实例的证据和可宣称影响，生成完整结构化结果；按 report-schema 固定顺序输出一份主报告及四个原有视图，威胁概览置于问题清单之前。默认运行 render-report.py 校验并生成 Markdown，不让排版改写结论；统计遗漏、未验证原因和实际耗时/token。确认问题后给出针对真实实现的修复方向，不自动修改被扫描业务代码。
