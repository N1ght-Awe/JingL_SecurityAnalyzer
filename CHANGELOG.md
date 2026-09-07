# 2.0.1 — 聚焦高价值目标

扫描后依据风险和证明价值选择验证目标，只展开必要的真实链路。简化主流程与配套说明；报告契约保持 2.0.0，保留原有状态和证据要求。

# 2.0.0 — 分级后选择验证

基于 1.1.0（`1866630`）独立改进。主流程、结论和报告语义发生变化，因此升级主版本；不代表已验证所有业务场景。

## 已实现

- 启动大量必读改为按阶段与类型读取，移除重复证明文案、教学案例和子 Skill 示例代码。
- P0–P3 统一为严重度兼紧迫度，保留初评、暂定标记与调整理由；P3 不代替误报。
- 去重后再深审和选择验证，增加 POC 生成/执行及 HTTP 提取规范，复用实际项目环境。
- 统一源码确认、实际确认、待验证、缺源码、待审查与误报语义；增加验证范围、对照及原始证据要求。
- 修正路径边界、DNS 校验、反序列化、CORS、权限链和制品信任判据；保留 18 类范围及跨仓关联。
- 增加标准库报告校验工具和合成数据回归，检查状态组合、计数、ID、证据路径与 SHA-256。校验器不执行目标、不生成 POC，也不能替代漏洞逻辑评审。

## 兼容与边界

保留子 Skill 路径和四个报告视图名称。旧 priority 曾有排队语义，不能无审查地当新严重度；旧“确认”不能无执行证据迁成新“确认”。新报告用 2.0.0，旧版留原件，接入方按 [迁移规则](shared-references/report-schema.md) 显式适配。工具不会静默转换旧报告。

现有模型平台负责搜索、代码读取、生成测试、执行及表格渲染；本版本没有新增扫描服务、自动漏洞利用引擎或业务代码重写器。

## 后续版本对照

在同一真实目标提交上固定模型、提示、范围及运行环境，分别运行待比较版本。比较规则效果时用同一模型；模型不同则单独标注，不能把差异归因于规则。

收集完整 JSON、原始证据、模型用量（不可得则 null）、墙钟时间、构建/重试及覆盖缺口。逐根因对齐，列双方独有、共同命中但结论不同、未审/未验证项。人工复核至少覆盖高危与双方差异，再决定合并哪些规则。

不以“确认数更多”或“扫描更快”单独判优；同时核对真阳性、误报、可能漏检和证明范围。当前仓没有完整业务基准，真实扫描表现待此阶段验证。

## 判据核对来源

维护参考的一手资料（2026-09-07 核对）；实际依赖版本和部署条件仍需扫描时读取，通用文档不是目标事实。

- [OWASP SSRF 防护](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)：解析与重定向。
- [OWASP 反序列化](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)：输入信任、类型与配置。
- [OWASP CSV 注入](https://owasp.org/www-community/attacks/CSV_Injection)：消费及转存语义。
- [Fetch CORS 凭据规则](https://fetch.spec.whatwg.org/#cors-protocol-and-credentials)：实际浏览器共享条件。
- [Maven 目录](https://maven.apache.org/pom.html#directories)、[JUnit 4 Test](https://junit.org/junit4/javadoc/4.13/org/junit/Test.html)：验证工程与用例状态。
