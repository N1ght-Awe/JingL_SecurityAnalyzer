# 代码仓边界清单

用户提供的扫描目标可以是一个汇总根目录，根目录下每个独立子目录代码仓均纳入扫描范围。阶段1先枚举这些子目录并创建此清单；阶段6.5用它匹配跨仓链路，不能仅凭服务名称猜测。

```yaml
repositories:
  - repo_id: repo-a
    path: /scan/repo-a
    service_names: [service-a]
    inbound: [{protocol: HTTP, endpoint_or_topic: /api/upload, auth: Bearer}]
    outbound: [{target_repo: repo-b|unknown, protocol: HTTP, endpoint_or_topic: /api/install}]
    shared_stores: [s3:artifact-bucket]
    shared_credentials: [credential-reference-only]
    evidence: [path/file:line]
    unknown_boundaries: [未定位的Feign目标]
```

## 匹配规则

- 仅以代码、配置、部署清单或已提供仓边界的直接证据建立关联。
- 目标仓未提供时使用 `unknown`，并将跨仓证据缺口纳入“缺失关键源码”。
- 上传、制品存储、下载、安装/执行必须分别记录，供供应链子Skill串联。
