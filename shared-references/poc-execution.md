# 执行与证据采集

遵循用户已有授权及平台权限。扫描请求本身不授权访问生产系统、使用真实凭据或执行有副作用的网络测试。已有明确授权不重复询问；源码分析和验证计划可独立继续。

1. 记录 `goal`、`scope`、目标提交、真实类/方法、环境、依赖、配置摘要及替换边界。
2. 检查项目原有构建与测试布局。Maven 自定义单目录使用 sourceDirectory/testSourceDirectory，多目录用项目已有机制；不要生成无效 POM 字段。优先使用现有 wrapper，不随意升级依赖。
3. 设置单次构建/测试超时、资源限制、工作目录、隔离测试数据和清理方式。先编译/收集测试，再执行指定用例，核查非零测试数量和退出状态。
4. 运行漏洞触发和安全对照。测试实例之间不可依赖 JUnit 字段状态；文件和服务资源显式准备及释放。测试通过仍需核对断言是否真正覆盖目标。
5. 保存命令、时间、exit_code、stdout/stderr、测试报告和关键行为证据。凭据脱敏，原始证据使用本地引用及 SHA-256 摘要；模型只读必要片段。
6. 按 proof-schema 更新状态。构建/依赖不可得为 BLOCKED；超时为 TIMEOUT；零测试、断言不成立或无法支持目标为 FAILED，不宣称复现。

默认首次失败后最多两次有针对性的修复重试。每次记录改变原因，禁止改目标逻辑或放宽断言来通过。无新信息停止重复尝试，保留源码结论和待办。

复用构建产物需匹配源码、规则、配置、依赖和目标；不能复用上一次请求的授权状态、测试数据或结论来掩盖差异。扫描报告不得使用“POC 已生成”代替“POC 已执行”。

## 2.3.2 执行绑定

先保存本轮候选与supervision读取回执，明确待执行finding的id、instance_key、repo_id及validation.goal/scope。执行前核对实际授权的命令、测试目标和对照；用scripts/execution_evidence.py采集，不手写成功回执。输入命令采用JSON参数数组，不隐式拼接shell：

```powershell
python scripts/execution_evidence.py <report.json> --repo-roots <repo-roots.json> --evidence-root <证据目录> --finding F-1 --cwd <测试工作目录> --environment <环境说明> --timeout 120 --command-file <command.json>
```

`repo-roots.json`为`{"backend": "实际本地仓根目录"}`形式的repo_id映射，涵盖目标读取证据中的全部仓库；`command.json`为实际命令参数数组，例如`["mvn", "-Dtest=已存在的目标测试", "test"]`。示例不代表项目必有该测试或Maven，使用实际工具/参数。Windows项目wrapper需要shell时由调用方显式声明经核对的启动方式。证据目录在被测仓外，测试工作目录须实际存在。

工具按本实例supervision中保留的全部read回执，以及finding_ids明确关联该实例且outcome=applicable的防护知识全部指纹绑定源码；共享防护即使在其他实例下读取，也进入本实例sources。再从所给仓根实读这些文件，执行前摘要不符就停止；命令结束后再核对，变化/缺失记录为source_changes，不能PASSED。回执保存run_id、明确列出的targets（id/instance_key/repo_id/goal/scope/sources）、仓库声明revision/path、命令及argv、cwd、environment、executed_at/finished_at、退出码/超时及cleanup_error和原始stdout/stderr日志。revision/path从报告复制，是声明元数据；脚本不将其说成实际测得的Git提交，实际实读的是文件摘要。

超时后使用Windows进程树或POSIX进程组终止并有界收尾，尽力清理；不能宣称一定没有残留进程，也不能将timeout说成严格总耗时上限。清理失败写入回执和原始日志的cleanup_error，保持TIMEOUT且不得PASSED；cleanup_error非空时由操作人员确认残留进程已处理后再重跑。该处理仅属于执行采集工具，不改变原搜索工具的行为。

将返回的execution_receipt放入对应validation，原样带入command/environment/executed_at/exit_code，将返回的原始日志引用纳入artifacts；其他测试报告和行为证据继续保留。脚本不修改报告，不决定漏洞状态。由审查者核实真实目标、测试断言及安全对照后，才按proof-schema设置target_executed/controls_passed/result_supported与status。退出码0或日志里写“成功”不足以给PASSED。

一条suite确实覆盖多个实例时，执行前重复`--finding F-2`等参数，明确列出所有覆盖ID；每个实例仍有独立goal/scope和源码绑定，逐项审查具体测试/断言，不能由根因相同推出同样已运行。复核新增/替换read快照、关联适用防护、目标或范围改变后，重新取得匹配执行证据，不删除必需读取回执以迁就旧日志。

未运行或失败可不提供execution_receipt，保留NOT_RUN/BLOCKED/FAILED/TIMEOUT等真实状态与缺口；一旦提供回执，身份、摘要、执行字段和日志引用必须一致。历史2.3.1等按原契约读取，不补造新回执；旧规则携带新字段会拒绝静默降级。绑定用于发现串错证据，不证明命令实际调用业务目标、达到真实环境召回率，或抵御人为伪造整套本地证据。
