---
name: SSRF漏洞分析
description: CWE-918 服务端请求伪造漏洞分析；用于审查不可信 URL、主机、端口、路径或重定向进入服务端 HTTP、文件或云元数据请求的情况。
---

## 1. 漏洞概述

仅在外部可控目标能驱动服务端发起请求，且目标限制不能阻止内网、回环、链路本地或云元数据访问时确认。

## 2. 危险点清单

- `RestTemplate`、`WebClient`、Feign、OkHttp、Apache HttpClient、`URL.openConnection()`。
- 用户可控回调 URL、图片/文档抓取、代理、Webhook、重定向和 DNS 解析结果。

## 3. 分析步骤

1. 追踪 URL 的 scheme、host、port、path 是否分别可控。
2. 检查解析前后 IP、IPv4/IPv6/整数和 DNS rebinding；检查重定向是否逐跳复验。
3. 核验协议白名单、主机/IP allowlist、私网与元数据地址拒绝及端口限制。
4. 读取实际 HTTP 客户端配置，记录认证头、代理、TLS 与响应使用方式。

## 4. 证据闭合验证

`Source` 为请求字段等；`Propagation` 为 URL 构造；`Sink` 为出站客户端；`Sanitizer` 为解析后目标校验；`Guard` 为网关/权限；`Transport` 为代理和 TLS；`Preconditions` 为可调用接口；`Impact` 为内网探测、元数据/凭据读取或请求代发。

## 5. 防护措施清单

**强防护：** 固定服务发现地址，或解析后只允许精确主机/IP+scheme+port，按业务边界约束实际连接 IP（校验与连接一致），核验全部解析结果，并禁用或逐跳复验重定向。

**弱防护：** `startsWith("https://")`、仅正则校验 URL、仅禁止 `localhost`、只在 DNS 解析前检查字符串。

## 6. 常见误报模式

- URL 为硬编码服务地址或由受控配置中心提供。
- 请求目标通过解析后精确 allowlist 限定，且重定向被禁用或复验。

## 7. 判定标准

以下为源码审查判据；最终结论与执行状态统一遵循 shared-references/proof-schema.md。

源码确认需证明可控目标越过业务允许的请求边界及具体影响；允许抓取任意公开 URL 不自动构成 SSRF。误报需证明相关目标与连接行为受有效约束。缺失调用方或校验实现时标记缺失关键源码。

## 8. 置信度评估

高：可控 host 到达请求 API 且可访问敏感网段；中：只确认 URL 局部可控；低：仅客户端实例存在。

## 9. 核心纪律

不得把 HTTP 客户端本身当作 SSRF；必须证明目标控制及网络边界绕过可能性。
