---
name: XXE漏洞分析
description: CWE-611 XML 外部实体漏洞分析；用于审查不可信 XML 到达 Java 或其他语言 XML 解析器时，DOCTYPE、外部实体、外部 DTD 和 XInclude 防护是否完整。
---

## 1. 漏洞概述

仅当不可信 XML 被可解析外部实体的解析器处理，或解析器安全特性无法证明启用时确认。影响包括本地文件读取、SSRF、拒绝服务。

## 2. 危险点清单

- `DocumentBuilderFactory`、`SAXParserFactory`、`XMLInputFactory`、`SAXReader`、`TransformerFactory`、`SchemaFactory`。
- XML 上传、SOAP、SAML、配置/导入文件和跨服务 XML 负载。

## 3. 分析步骤

1. 追踪 XML 内容来源到每个解析器实例，不能以项目内其他解析器配置替代。
2. 读取工厂设置：禁用 DOCTYPE、外部通用/参数实体、外部 DTD，并限制外部访问；StAX 需禁 DTD 和实体替换。
3. 检查解析器、转换器、Schema 和 XInclude 是否复用同一安全配置。
4. 记录实体解析后可访问资源和网络边界。

## 4. 证据闭合验证

Source 为不可信 XML；Propagation 为流/字符串传递；Sink 为解析调用；Sanitizer 为该实例的完整安全特性；Guard 为上传/接口控制；Transport 为跨服务 XML；Impact 为文件、内网或资源耗尽。

## 5. 防护措施清单

**强防护：** 在确切工厂实例上禁用 DOCTYPE 和全部外部实体/访问，并对不支持的特性失败处理。

**弱防护：** 仅 `setExpandEntityReferences(false)`、仅禁用一个实体开关、创建安全工厂后实际使用另一实例。

## 6. 常见误报模式

解析内容为固定可信资源；确切实例已完整禁用外部访问；仅生成 XML 不解析外部输入。

## 7. 判定标准

确认：可控 XML 到达未完整加固的解析器。误报：能证明该实例完整禁用外部解析。配置/调用链不可见时标记缺失关键源码。

## 8. 置信度评估

高：Source 和不安全 parse 调用闭合；中：特性设置缺失或未知；低：只发现工厂类。

## 9. 核心纪律

特性名称和默认值因实现而异；必须读取实际初始化与异常处理。
