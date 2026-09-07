# JingL Security Analyzer 2.0.0

面向 Java / Spring Boot / Jalor 的 18 类漏洞分析规则集。提供给现有模型平台后，以“`jingl 扫描 <代码仓或汇总根目录>`”触发，无需部署独立扫描平台。

## 工作方式

先批量发现候选并去重分级，再深审高风险路径，按漏洞目标选择最小充分验证。主入口精简，类型规则、验证和报告契约按需加载。

- P0–P3 同时表达严重度与处理紧迫度；保留初评、终评依据及待定标记。
- 源码结论与执行状态分开：待审查、缺失关键源码、待验证、源码确认、确认、误报。
- 局部模拟必须使用真实目标实现；权限等目标需保留实际安全链。POC 生成、构建成功或 mock 输出不算漏洞复现。
- 保留跨仓调用、身份、传输和制品关联；不根据框架注解、内网地址或库名称自动判安全。
- 验证失败、环境缺失、预算耗尽都保留在报告里，不变成误报或消失的候选。

## 结构

| 位置 | 用途 |
|---|---|
| `skill.md` | 触发、流程、按需读取和预算 |
| `shared-references/` | 18 份范围、证明、验证和报告引用 |
| `skill/` | 18 类专项规则，不含教学代码和固定 payload |
| `scripts/validate-architecture.ps1` | 路由、版本、文件和子 Skill 结构检查 |
| `scripts/validate-report.py` | JSON 报告状态与原始证据摘要检查 |
| `tests/` | 维护时使用的契约回归，不随扫描加载 |
| `CHANGELOG.md` | 版本变化、迁移与真实环境对照方法 |

保留既有小写 `skill.md` 路径，供已接入的模型平台继续使用。本仓是平台读取的规则包；需要平台原生 Skill 安装结构时，由接入层适配文件命名与元数据。

## 校验

需要 PowerShell，以及 Python 3.11+（仅标准库）。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/validate-architecture.ps1
python -m unittest discover -s tests -v
python scripts/validate-report.py <report.json> --evidence-root <报告根目录>
```

报告保留四个视图：漏洞扫描报告、传输链路探测分析、扫描统计、跨代码仓调用链分析。完整候选留在 JSON；旧报告迁移要求见 [报告契约](shared-references/report-schema.md)。

当前验证覆盖规则结构与报告契约，未附完整业务目标仓，不宣称已证明真实扫描准确率、召回率、半小时完成或 token 节省比例。
