# JingL Security Analyzer

面向 Java / Spring Boot / Jalor 代码仓的安全扫描 Agent 规则集。将本目录提供给模型后，使用“`jingl 扫描 <代码仓或汇总根目录>`”触发扫描。

## 核心能力

- 覆盖 SQL 注入、命令注入、路径穿越、SSRF、权限控制、反序列化、供应链与签名校验缺失等 18 类风险。
- 以 Source → Propagation → Sink → Sanitizer → Guard → Transport → Preconditions → Impact 证据闭合为确认门槛。
- 支持多代码仓目录的调用链、共享凭据与供应链关联分析。
- 区分 `确认`、`误报`、`缺失关键源码`；不以模糊的“可能存在漏洞”代替证据。
- 默认仅作源码分析；工具验证仅限用户明确授权的测试环境。

## 结构

- `skill.md`：主控流程、触发方式和执行纪律。
- `shared-references/`：扫描索引、调用链、防护分类、报告与覆盖统计契约。
- `skill/`：18 个专项漏洞分析子 Skill。
- `scripts/validate-architecture.ps1`：规则结构一致性校验。

## 当前范围

正式覆盖 Java / Spring Boot / Jalor。报告会记录 Skill 与规则版本、扫描范围、覆盖统计、跳过项和分析局限性。

## 校验

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\validate-architecture.ps1
```
jingl-analyzer/
├── skill.md                          # 本文件：主入口
├── shared-references/
│   ├── source-routing.md             # 项目画像 + 输入源路由
│   ├── scan-index.md                 # 轻量候选发现规则
│   ├── candidate-ranking.md          # P0/P1/P2/P3候选排序
│   ├── proof-schema.md               # 证据闭合 + 结论状态 + 报告字段
│   ├── sanitizers.md                 # 强/弱防护分类
│   ├── proof-patterns.md             # 结构化证明模板
│   ├── call-chain-tracing.md         # 调用链追踪方法论
│   ├── cross-repo-tracing.md         # 跨代码仓调用链追踪方法论
│   ├── security-tool-probing.md      # 安全工具辅助传输链路探测
│   ├── subskill-contract.md          # 子Skill最小判定契约
│   ├── agent-output-schema.md        # 并行Agent结构化输出与接收校验
│   ├── repo-boundary-manifest.md     # 跨仓边界清单
│   ├── report-schema.md              # Finding与四Sheet渲染数据契约
│   ├── regression-matrix.md          # 规则修改后的最小回归矩阵
│   └── coverage-metrics.md           # 扫描范围与覆盖量化口径
└── skill/                            # 18个专业漏洞分析子Skill
    ├── SQL注入/skill.md
    ├── XSS/skill.md
    ├── SSRF/skill.md
    ├── 反序列化/skill.md
    ├── 命令注入/skill.md
    ├── 路径穿越/skill.md
    ├── 权限控制/skill.md
    ├── XXE/skill.md
    ├── 表达式注入/skill.md
    ├── 不安全反射/skill.md
    ├── 敏感信息写入日志/skill.md
    ├── 硬编码/skill.md
    ├── 网络安全配置/skill.md
    ├── CSV注入/skill.md
    ├── 弱随机数/skill.md
    ├── 资源消耗/skill.md
    ├── 输入校验/skill.md
    └── 供应链与签名校验缺失/skill.md
