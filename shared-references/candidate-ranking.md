# 严重度与审查顺序

P0–P3 为项目现有严重度兼紧迫度，字段保持 `priority`。证据完整性、验证状态和置信度单列，不能用级别替代。

| 级别 | 判断基准 |
|---|---|
| P0 | 紧急：可信攻击前提下可造成关键系统控制、大范围跨租户敏感数据或等价严重影响 |
| P1 | 高：明确高价值数据/操作、显著越权或高影响执行风险，需要优先处理 |
| P2 | 中：影响或范围有限，或需要显著额外条件的安全缺陷 |
| P3 | 低：影响较小但仍成立的安全缺陷 |

按实际业务、权限、可达性、影响范围及补偿控制论证，不按 CWE 名称、是否登录、是否完成 POC 自动映射。未知严重度允许 null 并记录待评原因；有高后果依据的不确定候选按 P0/P1 暂定优先审查。

`initial_priority` 保存初评；`priority` 是当前评估；`grade_basis` 说明依据和调整理由；`grade_provisional` 表示未定级。终评前不足以确定的环境条件保留在理由中，不伪造生产事实。

筛选出的 P0/P1/P2 必须逐条深审并进入深度验证；尚未完成的项标“待审查”并说明原因。P3 保留在结构化结果中，不默认进入深度验证；后续证据改变分级时重新路由。明确排除由 `status=误报` 表达，不降到 P3 代替排除。

分级后的验证对象是筛选出的 P0/P1/P2，不再增加主观的“高价值”门槛。依据每项漏洞影响确定验证深度和目标，再准备关键代码、对照及授权环境。环境缺失时保留原级别、验证任务和阻塞原因；不能因此排除该项。

## 发现登记与调用实例（2.3）

每轮使用仓外的独立证据目录，发现候选后、筛选或排除前即登记。使用 scripts/candidate_ledger.py 初始化一次 candidate-ledger.jsonl；中断后读取原文件继续，不重建清单。脚本只追加、拒绝覆盖和冲突ID，同一条完全相同的登记重试不会重复计数。串行写入；若进程崩溃留下 .lock，确认没有写入者并核验文件完整性后再移除锁，不能自动重置账本。

```powershell
python scripts/candidate_ledger.py --evidence-root <本轮证据目录> --run-id <本轮ID> init
python scripts/candidate_ledger.py --evidence-root <本轮证据目录> --run-id <本轮ID> add <candidate.json>
python scripts/candidate_ledger.py --evidence-root <本轮证据目录> --run-id <本轮ID> snapshot
```

candidate.json 字段为 id、repo_id、type、location（原始位置）、instance_key、entry、operation、evidence。前三个实例字段描述发现时的“入口/调用点 → 敏感操作及分支”，使用稳定符号与调用点标识，不仅用易漂移行号；定位未定时如实写已知线索和未知条件，不编造调用链。evidence 是 audit_evidence.py 返回的实际搜索/读取 `{path, sha256}` 数组，非空，绑定本轮与仓库。登记并不宣称漏洞成立。

一个可独立到达的调用点/操作/关键分支对应一个候选ID。同一实例的重复搜索沿用原ID；同根因的不同实例通过 related_findings 关联，各自保留 status、八维证据、validation 和 supervision。不得用A路径的误报/确认批量替代B路径；实现知识可复用，B路径的调用、结果使用及后续变化仍逐项核查。代表性PoC可以减少重复执行，但未实际执行的兄弟实例最多保留有充分证据的源码确认，不能复制PASSED。

最终 findings 的ID集合必须与完整账本一致：未审/延期保留待审查或待验证及缺口，排除保留误报及反证；同根因可关联修复说明，不能通过合并删掉兄弟实例。snapshot 返回值原样放入顶层 candidate_ledger，校验器从证据目录固定文件独立对账，不根据最终 findings 重建发现记录。finding 保留 instance_key/entry/operation；新定位写location，原位置保留账本；修正初始type需classification_reason。统计为候选实例数，不冒充独立根因数。

空结果也需初始化的空账本；这仅证明没有已登记候选被遗漏，不证明扫描充分。脚本与摘要能查出缺记录、旧快照和证据变更，不能阻止执行者从未登记发现，或同时改写账本及报告；它不是防篡改审计系统。无Python时保留原始登记与逐项去向并明确未做程序对账，不编造脚本执行结果。
