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

