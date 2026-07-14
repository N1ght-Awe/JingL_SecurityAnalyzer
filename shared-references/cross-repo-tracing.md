# 跨代码仓调用链追踪方法论

## 核心原则

跨代码仓调用链追踪是微服务/多代码仓架构下漏洞扫描的基本逻辑，不是可选步骤。一个代码仓的输入验证漏洞可能通过跨代码仓调用链在另一个代码仓中被放大为RCE。

## 触发条件

满足以下任一条件即执行跨代码仓追踪：
1. 扫描目标包含2个以上子项目/代码仓
2. 项目画像发现服务间调用配置（如`application.properties`中引用其他服务端点）
3. 调用链追踪到达代码仓边界（方法调用指向外部服务/接口）

## 跨代码仓调用关系发现

### 搜索目标

| 搜索维度 | 关键词/模式 | 说明 |
|---------|-----------|------|
| HTTP API配置 | `${xxx.server}/yyy/*`、`RestTemplate`、`FeignClient`、`WebClient` | 服务间HTTP调用 |
| 消息队列 | `@KafkaListener`、`@RabbitListener`、MQS Topic配置 | 异步消息通信 |
| WebSocket | `WebSocketHandler`、`@ServerEndpoint`、`wss://` | 实时双向通信 |
| MCP/Agent | `fastmcp`、`streamable_http_app`、`MCP Server` | Agent通信协议 |
| 共享存储 | `S3`、`OBS`、`bucket`、`minio` | 文件/对象存储共享 |
| 共享认证 | `SSO`、`IDAAS`、`OAuth`、`mtoken`、`X-AUTH-TOKEN` | 认证系统串联 |
| 共享凭据 | `Langfuse`、`Redis`、`Elasticsearch`配置 | 多代码仓共用同一凭据 |

### 记录格式

```
调用方代码仓: 
被调用方代码仓:
通信协议: HTTP/MQS/WebSocket/MCP/S3/SSO等
调用接口: 具体的URL路径或Topic
传输数据: 认证凭据、用户输入、文件内容等
安全机制: Token传递方式、SSL验证状态、签名校验等
```

## 跨代码仓漏洞链构建

### 6种常见跨代码仓漏洞链模式

| 模式 | 描述 | 示例 |
|------|------|------|
| **组合漏洞链** | 代码仓A的漏洞→代码仓B的漏洞，组合放大 | A文件上传无校验→B路径穿越→任意文件写入 |
| **凭据横向扩展链** | 多个代码仓共享同一凭据，一个被攻破全部受影响 | 3个项目共享Langfuse secret_key，任一被MITM→3个项目数据泄露 |
| **越权链** | A的认证缺陷→B的敏感操作 | WebSocket仅校验userUid→MQS→B执行AI任务 |
| **异步攻击链** | A的输入→消息队列→B的消费处理 | A提交AI任务→MQS消息→B eval()代码执行 |
| **供应链攻击链** | A的Skill/插件下载→B的执行 | Gateway无认证→安装恶意Skill→pip install RCE |
| **传输放大链** | A的verify=False→B的凭据传输 | A http://传输SOA Token→B使用Token调用内部服务 |

### 构建规则

1. 代码仓A的finding（如文件上传无校验）→ 代码仓B的finding（如路径穿越）= 组合漏洞链
2. 代码仓A的传输安全finding（如verify=False）→ 代码仓B的凭据使用 = 凭据横向扩展链
3. 代码仓A的认证finding（如无SSO校验）→ 代码仓B的敏感操作 = 越权链
4. 多个代码仓共享同一凭据/密钥 → 一个被攻破全部受影响 = 凭据横向扩展链
5. 代码仓A的输入 → 消息队列 → 代码仓B的消费处理 = 异步攻击链
6. 代码仓A的Skill/插件下载 → 代码仓B的执行 = 供应链攻击链

## 深度追踪维度

### 1. 数据流追踪
用户输入 → 代码仓A → 序列化/传输 → 代码仓B → 反序列化/处理 → 危险操作

重点关注：
- 序列化格式（JSON/Fastjson/XStream/pickle）是否在跨代码仓时发生变化
- 传输过程中数据是否被增强（如添加认证头、注入上下文）
- 反序列化端是否有校验

### 2. 凭据流追踪
认证Token/Cookie → 代码仓A → HTTP头/Cookie → 代码仓B → 权限校验

重点关注：
- Token/Cookie在跨代码仓时是否被传递
- 传递方式是否安全（HTTP头 vs URL参数 vs Cookie）
- 接收端是否验证Token的有效性

### 3. 传输安全追踪
代码仓间通信的SSL/TLS验证状态、协议安全性

重点关注：
- http:// vs https:// 端点配置
- verify=False / createIgnoreVerifySsl() 等SSL验证关闭
- 中间人攻击可行性

### 4. 横向扩展追踪
一个代码仓的凭据泄露如何影响其他代码仓

重点关注：
- 共享的数据库/Redis/Elasticsearch凭据
- 共享的API Key/Secret Key（如Langfuse）
- 共享的S3/OBS访问密钥
- SSO/CAS认证的统一性

## 记录格式

```
链路ID: XC-001
链路名称: 代码仓A→代码仓B HTTP API
调用方: 代码仓A(技术栈)
被调用方: 代码仓B(技术栈)
协议/通信方式: HTTP/MQS/WebSocket等
传输数据: 具体传输的敏感数据
安全风险点: 关联的finding编号列表
跨代码仓漏洞链: 完整攻击路径描述
攻击入口: 攻击者从哪个代码仓进入
攻击影响: 跨代码仓攻击的最终影响
严重等级: P0/P1/P2
修复建议: 跨代码仓的修复方案
```

## 与其他阶段的关系

- **阶段1（项目画像）**：提供代码仓边界和技术栈信息
- **阶段6（调用链追踪）**：提供代码仓内部的调用链，跨代码仓追踪是其延伸
- **阶段7（传输链路探测）**：跨代码仓通信的传输安全是传输链路探测的重点
- **阶段8（证据闭合验证）**：跨代码仓漏洞链需要证明跨代码仓的完整证据链闭合

## 常见误区

1. **"接口是服务间调用所以安全"** — 服务间调用不是误报证明，攻击者可能通过其他代码仓的漏洞间接调用
2. **"内网通信不需要SSL"** — 内网MITM仍然可行（ARP欺骗、DNS劫持、被攻破的主机）
3. **"各代码仓独立评估即可"** — 跨代码仓漏洞链的影响远大于单个代码仓漏洞的简单叠加
4. **"共享凭据是运维问题不是代码问题"** — 代码中硬编码或配置的共享凭据是代码安全问题

## 分仓并行扫描后的跨仓关联分析（强制流程）

### 为什么需要这个流程

分仓并行扫描时，每个Agent只能看到自己负责的代码仓内部逻辑。这导致：
- 代码仓A的"文件上传无签名校验" → Agent认为"正常文件上传"
- 代码仓B的"下载后直接执行安装包" → Agent认为"正常更新逻辑"
- 两者组合 = 供应链RCE，但没有任何Agent能看到完整链路

**这不是规则问题，是架构问题。完善单仓扫描规则无法解决，必须在架构层面追加跨仓关联分析。**

### 强制流程

```
阶段A: 分仓并行扫描
  ├─ Agent1 扫描代码仓A → 返回 findings + 跨仓调用点清单
  ├─ Agent2 扫描代码仓B → 返回 findings + 跨仓调用点清单
  └─ Agent3 扫描代码仓C → 返回 findings + 跨仓调用点清单

阶段B: 跨代码仓关联分析（主Agent执行，不可跳过）
  ├─ Step1: 收集各Agent返回的跨仓调用点，构建全局跨仓调用关系图
  ├─ Step2: 将不同代码仓的finding通过跨仓调用关系串联
  │   ├─ 组合漏洞链：A的输入校验缺失 → B的危险操作 = 放大攻击
  │   ├─ 凭据横向扩展：A的verify=False → B的凭据传输 = 凭据泄露
  │   ├─ 供应链攻击：A的下载/分发 → B的执行 = RCE
  │   └─ 异步攻击链：A的输入 → MQ → B的消费 = 间接攻击
  ├─ Step3: 识别多代码仓共享凭据，评估横向影响
  ├─ Step4: 特别关注"下载→执行"模式（安装包/插件/技能/配置）
  └─ Step5: 新增跨仓finding，标注涉及的代码仓和完整攻击路径
```

### 跨仓调用点清单格式

每个分仓Agent必须在返回finding列表的同时，返回跨仓调用点清单：

```
跨仓调用点:
  - 类型: 出站调用/入站被调/共享存储/共享凭据
    目标代码仓: 代码仓B
    通信方式: HTTP/MQ/WebSocket/S3/SSO
    接口/路径: /api/version/upload, /api/version/download
    传输数据: 安装包文件、认证Token
    安全机制: 无签名校验、verify=False
```

### 实际案例：coplit代码仓供应链RCE

```
代码仓A (HdpCopilotService/Java):
  - addVersion() 接受安装包上传，无签名校验、无文件类型校验
  - uploadFileToS3() 直接存入S3
  - getNewVersion() 返回S3下载路径
  - @JalorOperation(code=IMPORT) 但无 @DataRightCheck

代码仓B (HdpAgentClient/Python):
  - check_version() 从服务端获取最新版本信息
  - _download_and_install() 下载安装包，无签名验证、无MD5/SHA256校验
  - _run_installer() 直接执行: subprocess.Popen([installer, "/S"]) 静默安装

跨仓漏洞链:
  任意W3用户上传恶意安装包 → 客户端检查更新 → 自动下载 → 静默执行 → RCE

单仓扫描结果:
  Agent3看到addVersion() → 认为"正常文件上传" → 未报
  Agent1看到subprocess.Popen() → 认为"正常更新逻辑" → 未报

根因: 分仓扫描人为切断调用链，每个Agent只看到自己代码仓的"正常"逻辑
修复: 追加阶段B跨仓关联分析，发现A的输出(文件)成为B的输入(执行)时无校验
```