# 分工输出契约

仅在平台支持且用户授权并行时使用；串行使用同样的候选数据结构。按模块或互不重叠的类型划分范围，避免多个执行者重复读整仓。主审负责跨仓关联、结论和报告。

每份结果返回：assigned_scope、actually_reviewed、skipped、truncated、candidates、boundary_edges、evidence_refs、cost（不可得为 null）。候选使用 report-schema.md 字段，未深审为待审查；主审不能直接采信子任务的确认标签。

候选需有稳定 ID、仓库/版本、源位置、类型、初评及依据、已读实现、未读缺口。证据使用文件引用及摘要，不复制大段日志。分工数量不证明覆盖度；主审核对范围并集、缺口、重复和跨仓边是否接上。
