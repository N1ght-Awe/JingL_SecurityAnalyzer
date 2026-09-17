# 执行监督与定向补查

监督是报告前的另一轮证据审查，不要求多 Agent 平台。可由同一模型切换到复核步骤；平台支持独立审阅者时可使用，但换模型不是正确性保证。先读取原始搜索结果、源码读取记录和当前结论，不只读取分析者总结。

## 检查与停止条件

1. 先核对可用的语义导航是否实际查询了定义、必要的调用者/被调用者及具体实现；未使用须说明不适用、能力缺失或索引失败的具体原因，不能只填“已使用AST”。平台原始调用结果与读取回执一起审查，检查工作清单有无漏掉返回的相关实现。再核对工具是否成功、输出是否截断、范围和忽略规则是否遗漏资产。执行过命令不代表读完结果；只有预览时分段读取保存的结果。AST 结构位置不等于已解析的语义调用。
2. 从实际入口、Sink 所属模块及路由/中间件注册处重新寻找控制，不能只核对原清单。检查白名单、包装器、转义、失败分支、返回值使用、后续变换及配置。新发现的防护立即形成待读实现。
3. 对照八维证明义务及同路径反证，记录所需源码范围和实际读取回执。调用点已读而实现未读，或定义已读而调用/注册未知，都不能关闭义务。已审防护按 control-knowledge.md 复用，本路径适用性仍须核验。
4. 未解析的分派、回调、跨仓边和配置条件，记录精确缺口与下一步文件/查询。只补查受影响的义务，每轮保留新增证据；同一无进展操作不重复。默认最多两轮补查，仍不完整则停止并交付部分结果。
5. 源码确认、确认、误报均须监督 pass；其他状态可 pending/blocked，附缺口。误报须充分反证，不是搜索失败、调用方没搜到或防护名称命中。pass 不代替真实执行、不自动升级为确认。

## 原始记录工具

使用 scripts/audit_evidence.py 保存实际文件片段和搜索输出，不手写成功回执。evidence-root 必须位于被扫仓库之外，避免后续搜索命中自身证据。根参数位于子命令前：

```powershell
python scripts/audit_evidence.py --repo <仓库> --repo-id backend --run-id <本轮ID> --evidence-root <证据目录> search --scope src --text 'A' --pattern 'A($$$ARGS)' --lang Java
python scripts/audit_evidence.py --repo <仓库> --repo-id backend --run-id <本轮ID> --evidence-root <证据目录> read src/Allowlist.java 1 80
```

语义导航优先使用平台已有能力，保存原始请求/响应供监督复核；此脚本是补充搜索与源码读取工具，不替代调用层次查询。search 尝试已安装 ast-grep 和 rg，保留命令、退出码、超时、stdout/stderr。AST 缺失/失败时记录原因，退回文本定位与人工审读，不能称已生成完整调用图。scope、语言及忽略规则须与资产清单对账，零结果不能排除防护。不自动安装工具、下载依赖、构建或运行目标项目。

read 支持 UTF-8 源码，每次最多200行/16000字节，超限要求分片，其他编码先以平台合适工具核验并保留原件。保存完整源文件快照、实际片段、行号、run_id/repo_id和摘要，返回回执路径/摘要；path 使用解析后的仓库相对路径。生成内容不等于模型理解；宿主截断、未读结果和语义误判仍由监督者检查。快照含业务源码，证据目录仅用于本地审查，不随规则包或公开报告上传。源码/配置变化后重读受影响部分，同一报告不能混用同文件不同快照。

## 2.2 报告字段

顶层 supervision 数组，每条 finding 恰有一条记录：

- finding_id、decision（pass/blocked/pending）、rationale（复核判断）、repair_rounds（0..2）、gaps（字符串数组）。pass 的 gaps 必须为空；未通过须列具体缺口。
- pass 另需 receipts：回执ID到 `{path, sha256}` 的对象映射，path 相对 evidence-root。校验器重算回执/快照摘要，检查本轮ID、登记仓库、源码片段和行号。
- checks：Source、Propagation、Sink、Sanitizer、Guard、Transport、Preconditions、Impact、counterevidence 九项，每项 `{state, reason, reads}`。state 为 resolved/not_applicable/gap，pass 不允许 gap。not_applicable 也需支撑判断的源码范围。源码确认/确认的 Source/Propagation/Sink/Impact 及所有结论的 counterevidence 不可 not_applicable。它描述审查义务，不替换 evidence 的四种证据状态。
- reads 为非空数组，元素 `{receipt_id, repo_id, path, start, end}`，所需范围须被对应 read 回执覆盖。不能为了过校验把整个防护函数缩成调用点一行。多个片段分别引用。
- discovery_receipt_ids：非空 search 回执ID数组，保留复核时重新搜索控制的原始记录。discovery_assessment 说明采用的语义导航能力及原始结果位置、必要的降级原因、补查范围、失败/忽略项、结果阅读情况、新发现控制及去向；只有预览不得写已审完。
- edges：非空数组，元素 `{from, to, resolution, reason, reads}`，记录与证明目标有关的调用/字段传递/控制生效边。resolution 为 resolved/excluded/unresolved；pass 仅 resolved/excluded，excluded 须源码反证。同函数候选记录输入到操作的边；入口不成立的误报记录被排除候选边，不强造不存在的整链。

校验器确认记录完整性、引用和状态一致，不能自动发现所有隐藏调用或证明模型认真阅读。自填理由、伪造回执、遗漏义务无法仅靠 JSON 校验消除，仍须原始执行记录与源码语义复核。缺口不得通过删 finding、改误报或换历史 schema 隐藏。
