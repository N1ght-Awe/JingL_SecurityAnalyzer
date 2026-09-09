---
name: 反序列化漏洞分析
description: CWE-502；审查 Java 原生及第三方反序列化的类型、配置、输入信任和可达行为。
---

## 1. 漏洞概述

反序列化入口不自动等于 RCE。输入信任、实际版本/类型配置、可达类/回调和危险副作用共同决定结论；对象构造、类型混淆、资源耗尽与命令执行分别证明。未知缺陷不要求先有 CVE。

## 2. 危险点清单

- ObjectInputStream/readObject/readResolve/resolveClass 与对象过滤器、代理类处理。
- Fastjson parse/parseObject、autoType/SafeMode/自定义类型回调；Jackson 多态、default typing、PTV 和自定义反序列化器。
- XStream 类型权限、Kryo 注册模式、Gson 自定义 TypeAdapter。
- Redisson Codec、Spring Session/Redis 序列化器、MQ 与数据库二次读取；JDK/JSON/其他格式都检查实际配置。

## 3. 分析步骤

1. 定位实际解析实例与入口，追踪不可信字节、类型选择和可信边界；内网存储/本地文件非自动可信。
2. 从实际构建解析/锁定依赖核验版本与运行类路径，不能只信声明版本。已知 CVE 查官方受影响版本、配置及前提；修复某 CVE 不等于整个库永久安全。
3. 读取实例/global 过滤、SafeMode/autoType、PTV、XStream 权限、Kryo 注册及实际 Codec，检查覆盖/优先级/异常处理。未重写 resolveClass 不等于没有 ObjectInputFilter。
4. 检查类型允许范围、嵌套对象、可达 gadget/自定义回调及资源限制；包前缀允许的类也可能有危险能力。
5. 根据目标影响检查实际触发路径；不能把 Spring 数据绑定类 CVE 泛当任意反序列化 Gadget，也不要求 DoS 必须有 RCE 链。
6. 控制侧关注解析实例覆盖、Redis/Session/MQ 配置与实际环境差异。控制侧通用步骤见 shared-references/protection-audit-methodology.md；已审实现按 shared-references/control-knowledge.md 复用，逐路径核验调用、适用性与后续影响。

## 4. 证据闭合验证

Source→字节/字段传播→实际解析实例→允许类型/逻辑→目标影响；Sanitizer 为类型/能力/资源约束，Guard 为输入/入口权限，Preconditions 为版本/配置/类路径等必要条件。存在依赖、parse 成功或异常都不等于命令执行。

## 5. 防护措施清单

精确类型和能力约束、有效对象过滤、适用 SafeMode/PTV/注册策略、解析前验证绑定实际字节与可信来源的签名、对应资源限制。JSON/Protobuf 或某个 Serializer 类名不单独判安全；GenericJackson2JsonRedisSerializer 需核验实际 ObjectMapper 多态配置。

## 6. 常见误报模式

真实输入不能被相关威胁主体影响，或实际配置完整阻断所述危险类型/行为。白名单存在、较新版本、包名前缀、仅捕获异常或 Content-Type 不构成独立反证。

## 7. 判定标准

最终 status 与执行状态遵循 shared-references/proof-schema.md；下述为源码判据。源码确认需证明可控输入通过实际配置抵达类型/逻辑并产生可支持的目标影响，相关控制未阻断。已知 CVE 对照是证据来源，不是所有漏洞必要条件。缺实际类路径/实现/配置时按具体缺口分类。

## 8. 置信度评估

综合输入、版本、有效配置、可达类型和影响，不用“有 gadget 依赖”或“无白名单”单独给高置信。

## 9. 核心纪律

不硬编码笼统安全版本，不新增易受攻击依赖或重写目标来制造复现；调用真实目标并仅宣称实际观测到的能力。保留 Redis/Session 和自定义回调检查。
