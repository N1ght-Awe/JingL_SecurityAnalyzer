反序列化---
name: 反序列化漏洞分析
description: CWE-502 反序列化漏洞分析，包括Java原生、Fastjson、Jackson、Redisson等
cwe: CWE-502
cvss_base: 9.8
---

## 1. 漏洞概述

反序列化漏洞：攻击者操纵序列化数据，在反序列化时执行恶意代码。**严重** CVSS 9.8，可导致RCE、服务器失陷、数据泄露/删除、内网渗透。

## 2. 危险点清单

### 2.1 Java原生反序列化 — ObjectInputStream
```java
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();
```
允许任意类反序列化，未重写resolveClass限制类名则等同无防护。

### 2.2 Fastjson
```java
JSON.parse(userInput); JSON.parseObject(userInput);
```
`@type`字段可指定恶意类（如JdbcRowSetImpl）触发JNDI注入→RCE。关键配置：`setAutoTypeSupport(true)`高危，`setSafeMode(true)`安全。

| 版本 | CVE/绕过 |
|------|---------|
| ≤1.2.24 | CVE-2017-18349 |
| 1.2.25-1.2.69 | 多种autoType绕过（L前缀;、[开头、expectClass等） |
| ≤1.2.83 | CVE-2022-25845 |
| ≥1.2.83 | 安全版本 |

### 2.3 Jackson
```java
mapper.enableDefaultTyping(); // 高危：允许@class指定任意类
mapper.readValue(userInput, Object.class);
```
`enableDefaultTyping()`高危，默认`BasicPolymorphicTypeValidator`不安全，`allowIfSubType("com.example.")`白名单安全。安全版本≥2.14.0。

### 2.4 其他框架
- **Gson**：相对安全，但自定义TypeAdapter可能触发RCE
- **Kryo**：`setRegistrationRequired(false)`允许任意类，高危
- **XStream**：允许任意类反序列化，已知CVE-2021-39139~39152

### 2.5 Redisson反序列化
- **高危**：`JdkSerializationCodec`使用ObjectInputStream
- **中危**：`JsonJacksonCodec`/`Kryo5Codec`需检查内部配置
- **安全**：JsonJacksonCodec + 安全ObjectMapper配置

### 2.6 Spring Session反序列化
`JdkSerializationRedisSerializer`高危（默认），`GenericJackson2JsonRedisSerializer`安全。

### 2.7 依赖Gadget检查清单

| 依赖库 | 危险版本 | Gadget | 安全版本 |
|--------|---------|--------|---------|
| commons-collections | ≤3.2.1 | InvokerTransformer | 3.2.2 |
| spring-beans | ≤5.3.0 | CVE-2022-22965 | 5.3.18+ |
| Commons-Beanutils | ≤1.9.2 | BeanUtils Gadget | 1.9.4 |

## 3. 分析步骤

1. **识别反序列化点**：搜索ObjectInputStream/readObject、JSON.parse、ObjectMapper.readValue、Kryo.readObject、XStream.fromXML、JdkSerializationCodec、InitialContext.lookup
2. **输入溯源**：高危来源（HTTP请求/Socket/文件上传）→ 中危（Redis/数据库Blob）→ 低危（本地文件/内部配置）
3. **危害性验证**：检查序列化器配置（autoType/enableDefaultTyping/resolveClass/ObjectInputFilter）
4. **防护机制核验**：检查强防护（白名单/SafeMode/ObjectInputFilter）vs 弱防护（Content-Type检查/异常捕获/黑名单）
5. **业务影响评估**：评估严重性（高：无白名单+用户可控+存在Gadget / 中：弱防护 / 低：可信源+强防护）

## 4. 证据闭合验证

- **Source**：外部输入来源（HTTP请求、Socket、Redis数据等）
- **Propagation**：从输入源到反序列化入口的数据传递路径
- **Sink**：ObjectInputStream.readObject / JSON.parse / ObjectMapper.readValue等
- **Sanitizer**：类型白名单 / ObjectInputFilter / SafeMode / 安全配置
- **Guard**：认证、角色、接口访问控制
- **Preconditions**：攻击者必须能控制序列化数据内容 + 框架版本存在已知CVE
- **Impact**：RCE / DoS / 数据篡改

**三重检查（反序列化特有）**：①框架版本已知CVE ②序列化器配置（autoType/enableDefaultTyping/resolveClass）③依赖Gadget链

## 5. 防护措施清单

### 强防护
| 防护措施 | 代码示例 |
|---------|---------|
| ObjectInputFilter白名单 | `ObjectInputFilter.Config.createFilter("com.example.*;!*")` |
| resolveClass重写 | 白名单校验类名 |
| Fastjson SafeMode | `ParserConfig.setSafeMode(true)` |
| Jackson白名单PTV | `allowIfSubType("com.example.")` |
| 禁用enableDefaultTyping | 不调用`enableDefaultTyping()` |
| 安全序列化格式 | JSON/Protobuf替代Java原生序列化 |
| 非漏洞依赖版本 | Fastjson≥1.2.83、Jackson≥2.14.0 |

### 弱防护
| 防护措施 | 绕过方式 |
|---------|---------|
| 仅信任Content-Type | Content-Type可伪造 |
| 仅捕获异常 | 不阻止恶意类加载 |
| Fastjson黑名单addDeny | 新Gadget或类名变种绕过 |
| 升级版本但autoType仍启用 | 配置不当仍可利用 |

## 6. 常见误报模式

1. ObjectInputStream已配置ObjectInputFilter白名单（`com.example.*;!*`）— 攻击者无法反序列化任意类
2. Fastjson已开启SafeMode或版本≥1.2.83 — autoType被完全禁用
3. Jackson已配置白名单PolymorphicTypeValidator — 仅允许特定包的类
4. 反序列化数据来自内部可信源且经过签名验证 — 签名确保数据完整性
5. 使用JSON/Protobuf等安全序列化格式 — 不支持任意类实例化

## 7. 判定标准

### 确认风险
- ObjectInputStream无白名单/ObjectInputFilter，数据用户可控
- Fastjson启用autoType，或版本存在已知CVE
- Jackson启用enableDefaultTyping，允许任意类
- Redisson使用JdkSerializationCodec，Redis数据用户可写入
- 存在已知Gadget链

### 确认误报
- ObjectInputStream使用白名单或ObjectInputFilter
- Fastjson SafeMode=true / 版本≥1.2.83
- Jackson使用安全PolymorphicTypeValidator白名单
- 数据来源可信（配置文件/内部可信源+签名验证）
- 使用安全序列化格式，无多态反序列化

### 缺失关键源码条件
- 缺少序列化器配置代码 / resolveClass实现 / Fastjson/Jackson配置 / Redisson Codec配置 / pom.xml依赖版本

## 8. 置信度评估

- **高（95%+）**：ObjectInputStream无白名单+数据用户可控 / Fastjson autoType+版本有CVE / 存在已知Gadget
- **中（70%-95%）**：存在弱防护可能被绕过 / 数据来源需特定条件 / 序列化器配置不完善
- **低（<70%）**：数据来源可信 / 存在强防护但未确认生效 / 缺少关键配置代码

## 9. 核心纪律

1. **必须检查框架版本已知CVE**：版本号是危害判定的关键证据
2. **必须检查序列化器配置**：autoType/enableDefaultTyping/resolveClass/ObjectInputFilter决定安全性
3. **必须检查依赖Gadget链**：Commons-Collections、BeanShell、Groovy等
4. **必须追溯数据来源**：HTTP请求/Socket/Redis/文件等
5. **不能忽略Redisson**：JdkSerializationCodec使用ObjectInputStream，高危
6. **不能忽略Spring Session**：JdkSerializationRedisSerializer高危
7. **不脑补未看到的事实**：无法确认时标注"缺失关键源码"

> 【最高优先级】必须完成证据闭合验证：对每条finding证明Source→Propagation→Sink→Sanitizer→Guard→Preconditions→Impact证据链完整，调用链深度不是目标，证据闭合才是。参考 shared-references/proof-patterns.md 中对应漏洞类型的证明模板。