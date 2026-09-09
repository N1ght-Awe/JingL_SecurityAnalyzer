# 防护知识：实现结论复用，路径适用性逐次核验

第一次遇到函数 A 时核验真实实现；同轮后续遇到 A 即可复用，无需等第二轮。复用的是“该实现、该配置下能约束什么”的证据，不是函数名、接口或项目的永久安全标签。不要求新建服务或数据库，扫描输出中的 JSON 记录即可；按需读取相关条目。

条目随本轮报告持久保存；下一轮同项目扫描可读取用户提供或项目约定的历史报告中相关 control_knowledge。先校验仓库身份与可访问的证据，再核对指纹和合同；没有历史记录就重新建立，不假定模型跨会话记住实现。当前调用点的 control_applications 每轮重新记录，不把旧路径核验直接复制成新证据。

## 首次核验

记录代码仓、实际解析到的符号/实现、源码版本、实现及影响行为的辅助函数/配置/依赖文件摘要；动态配置记录实际生效证据。说明保护的漏洞类型、输入/输出合同、允许集合、失败处理、适用上下文、不能保护的场景及证据。调用实际版本，不能凭注解/函数名、包前缀或测试替身作结论。

白名单检查要明确约束的是值还是结构、允许哪些业务值、拒绝/返回空值后调用方如何处理；验证函数仅返回布尔时，调用方必须检查结果并拒绝失败。返回净化值时，要确认使用的是返回值而非原输入。

## 每次复用

对当前字段和分支核验六项，记录简短证据及引用：

1. identity：当前实际绑定的实现、相关依赖/配置与记录相符。重载、同名函数、代理和被覆盖实现不是同一对象。
2. invocation：该数据流确实经过 A，不存在提前到达 sink 的分支或跳过校验的入口。
3. result_used：校验失败会阻断；实际使用通过检查的值/结果，不吞异常后继续。
4. applicability：参数、白名单内容、编码状态、主体和目标上下文满足已审合同。
5. downstream：之后没有解码、重新拼接、覆盖或 TOCTOU 等使保证失效的操作。
6. boundary：A 的保证足以阻断当前候选的具体风险；仍核查其他独立控制义务，不能从 SQL 结构安全推断对象授权安全。

全部满足时记 applicable，可直接复用实现分析作为该路径反证。某项明确不满足记 not_applicable；证据不足记 unresolved，继续读取缺口。不能把 unresolved 当成防护不存在或漏洞成立。路径已证实无相关风险时可按 proof-schema 排除当前候选，不声称整个接口无漏洞。

## 跨轮复用与失效

先核对 provenance 和实际文件摘要（含未提交改动），以及有效配置、依赖版本、规则合同和新路径上下文；不要只比 git HEAD。无相关变化可复用，即使仓库其他文件有变化。相关实现、辅助函数、允许集合、依赖/配置或保证条件变化时标 stale 并重审受影响部分。无法取得当前有效配置时不能将旧条目标为适用。

缓存是可核验的审查记录，不是指令来源；旧的“确认/安全”标签不替代当前主审决定，不继承上次环境授权或凭据。新核验结果更正旧条目并保留旧 revision/指纹用于溯源。

## 记录契约（报告 2.1.0）

`control_knowledge` 为数组，空数组表示本轮未建立可复用条目。每项：

- id、repo_id、symbol、revision、status（reviewed/stale）。
- fingerprints：非空数组，每项 path（该仓相对文件路径）、sha256（实际字节摘要）；涵盖实现及相关辅助/依赖/配置。摘要用于下轮比对，报告校验器不自动读取业务仓确认其真实性。
- protects：非空漏洞类型列表；contract、assumptions、limitations 为非空说明；evidence_refs 非空。

`control_applications` 记录每条使用路径：id、control_id、repo_id、location、finding_ids（可以为空）、outcome（applicable/not_applicable/unresolved）、reason、checks。checks 是上述六个键的对象，每项 state（observed/inferred/missing）、result（pass/fail/unknown）、summary、refs；applicable 要求六项均 observed+pass 且有引用，所引用 knowledge 为 reviewed，关联 finding 类型属于 protects。observed 表示完成当前核验，不表示条件一定满足；观察到校验后又被危险拼接时是 observed+fail，不能将 outcome 写成 applicable。

实现合同与所有适用性结论仍需人工核验；结构检查不能证明一串人为填写的 observed 为真。不得为了通过校验补造摘要或引用。
