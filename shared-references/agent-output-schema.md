# 并行Agent结构化输出契约

并行Agent只返回发现和追踪结果，不给最终finding或“确认/误报”结论。使用下列字段；缺失字段必须显式写 `null` 和原因。

## 候选对象

```yaml
candidate_id: MOD-TYPE-001
vulnerability_type: SQL注入
location: path/file:line
match_rule: "${...}"
context: 简短上下文
source_evidence: {location: path:line, detail: 外部输入或间接输入}
sink_evidence: {location: path:line, detail: 危险操作}
priority: P0|P1|P2|P3
priority_reason: 基于可见证据的排序理由
visible_defenses: [{name: function_or_annotation, location: path:line, implementation_read: false}]
forward_trace: [入口, 调用1, Sink]
reverse_trace: [Sink, 调用者1]
trace_depth: {forward: 0, reverse: 0}
trace_complete: true|false
missing_evidence: [具体缺失环节]
```

## 跨仓与传输对象

每个Agent还必须返回 `cross_repo_calls[]` 和 `transport_signals[]`。前者包含调用方/目标/协议/接口或Topic/数据/安全机制；后者包含信号位置、客户端实例、全部已定位请求、敏感字段、追踪完整性。

## 主Agent接收校验

- P0必须有Sink和用户可控证据，或明确标记哪一项缺失；P1必须有Sink和至少一层来源追踪。
- `visible_defenses` 不得标“强/弱”；主Agent读取实现后才能分类。
- 相同候选ID、缺失位置、追踪深度不足且无豁免原因，均退回补充，不进入阶段5。
