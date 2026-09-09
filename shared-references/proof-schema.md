# 证据与结论契约

本文件是结论语义的唯一权威；子 Skill 的“确认判据”指源码审查条件，不能跳过这里的运行证据门槛。报告字段见 report-schema.md。

## 八维证据

Source、Propagation、Sink、Sanitizer、Guard、Transport、Preconditions、Impact 各记录 `state`（observed / inferred / missing / not_applicable）、`summary`、`refs`（证据引用）。不适用必须说明理由；未发现某类防护需给出已检查范围，不是空白即无防护。

确认路径必须证明真实来源/威胁主体、字段传播、危险行为、防护覆盖范围、授权边界、必要环境条件与相称影响。代码缺失、业务政策未知和运行环境未知是不同缺口。Transport 仅涉及网络时适用；TLS 缺陷不自动绕过签名、对象授权或服务端校验。

## 结论状态

| status | 必要条件 |
|---|---|
| 待审查 | 候选尚未完成深审；不得计入已确认数量 |
| 缺失关键源码 | 判断所需实现/调用方/跨仓代码确实未提供，列出缺失位置及接力方式 |
| 待验证 | 业务政策、环境或关键行为尚未知，或验证结果仍不能支持结论；说明具体缺口 |
| 源码确认 | 源码路径与适用条件已闭合，满足类型判据；只宣称静态证据支持的影响 |
| 确认 | 源码闭合且真实目标验证通过；预设目标、正负对照、原始证据齐全；不得超出实际验证范围 |
| 误报 | 可验证的同路径反证排除候选；不能只凭一次 POC 未复现、防护名称或无关键词命中 |

`source_closed` 是主审对源码证明义务的判断。源码确认/确认必须为 true，八维中不得有 inferred/missing；运行时未知条件若影响结论则保持待验证。不影响已经证明的局部问题的未知部署信息记录为影响边界，不扩大结论。

`validation.status` 独立取 NOT_RUN / BLOCKED / PASSED / FAILED / TIMEOUT / SKIPPED。FAILED 指预定漏洞目标未成立或执行失败，具体原因写入记录，不等同修复成功。构建错误用 BLOCKED 并保留工具错误。对照显示防护确实生效时可据额外反证判误报。

`validation.scope` 取 none / isolated / integration / end_to_end。isolated 必须调用实际目标方法/类且保留相关安全逻辑；省略过滤器的局部验证不得声称接口越权。integration 不等于生产部署；end_to_end 也只能涵盖实际测试链。

确认必须满足 PASSED、非 none scope、target_executed=true、controls_passed=true、result_supported=true、完整工具记录。模型写出的预期输出、手写同款漏洞代码、mock 的危险结果不算目标执行。

## 防护状态与证据状态

state 描述证据掌握程度，保持 observed / inferred / missing / not_applicable。missing 表示该维度所需证据缺失，不表示已经证明防护不存在。完成确切路径范围检查后，观察到缺少控制可记 observed，summary 写明缺失的是哪种控制及检查范围，refs 指向实际路径/配置证据；未读完为待审查，实现确实未提供为缺失关键源码，政策或部署未知为待验证。不得用 not_applicable 隐藏未知。

防护知识按 control-knowledge.md 复用；实现已审查不能代替当前调用点核验。缺少防护只是证明义务的一部分，仍需证明可控性、可达性、触发语义、授权边界、前提和影响。防护侧观察使用 control_observations，不能把其组件定义塞进 Source 或把输入通道塞进 Sink。

源码确认无需为了升级标签而伪造运行证据。真实局部执行可给确认，但 trigger/exploitation/validation.goal 必须限定已验证的局部属性；省略相关授权链不能声称接口越权。单次未复现不能判误报，充分同路径反证才可排除。

严重度遵循 candidate-ranking.md。执行失败不得降低严重度；源码确认可为 P0。风险置信度用证据描述，不输出无校准依据的百分比。
