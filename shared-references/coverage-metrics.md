# 扫描覆盖量化

阶段1建立基线，阶段3记录实际搜索与截断重试，阶段9将结果写入扫描统计。量化信息用于解释扫描边界；不得把未扫描、无法解析或零命中表述为“安全”。

## 必填统计

```yaml
scope:
  target_root: 用户提供的路径
  repositories_detected: 0
  repositories_scanned: 0
  repositories_skipped: [{repo: name, reason: 原因}]
files:
  java_total: 0
  java_read: 0
  java_skipped: [{path_or_pattern: path, reason: 生成代码|二进制|读取失败|超出用户范围}]
  xml_mapper_total: 0
  xml_mapper_read: 0
  config_total: 0
  config_read: 0
  build_files_read: 0
analysis:
  entry_points_found: 0
  vulnerability_types_enabled: [SQL注入]
  candidates: [{type: SQL注入, total: 0, p0: 0, p1: 0, p2: 0, p3: 0}]
  grep_truncations: [{rule: pattern, initial_count: 0, retry: 分目录/文件类型/精确模式, completed: true}]
  boundary_links_resolved: 0
  boundary_links_unresolved: 0
limitations: [未解析的动态反射调用]
```

## 统计规则

- Java文件总数以目标范围内生产源码为主；测试、生成、二进制和用户明确排除的目录必须分别记录，不可静默排除。
- XML Mapper、配置、构建文件分别计数，避免“Java文件已读”掩盖数据访问层或生效配置未覆盖。
- 发生Grep截断时记录初始数量、分片方式和是否完成；未完成的规则进入`limitations`。
- 每类漏洞必须记录P0/P1/P2/P3总数或明确说明未启用原因。
- 报告结尾必须说明：零候选仅代表已记录范围内未发现匹配证据，不代表整体不存在漏洞。
