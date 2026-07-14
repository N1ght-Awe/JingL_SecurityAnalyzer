 # 调用链追踪方法论

## 正向追踪（从入口到危险点）

1. Grep找到输入源：`@RestController`/`@GetMapping`/`@KafkaListener`等
2. Read输入源代码，找到方法参数和调用的Service
3. Grep搜索Service类名.方法名 或 Service注入变量名.方法名
4. Read Service代码，找到调用的DAO/Repository/Delegate
5. 逐层追踪直到危险操作点（SQL执行、文件操作、命令执行、HTTP请求等）

## 反向追踪（从危险点到入口）

1. Grep找到危险函数（如 new File(、ProcessBuilder、wrapper.last）
2. Read危险函数所在方法，记录方法签名
3. Grep搜索该方法被谁调用（搜索方法名或类名.方法名）
4. Read调用者代码，继续向上追踪
5. 逐层向上直到输入源或确认无用户可控路径

## 追踪深度要求

| 场景 | 最少追踪层数 | 说明 |
|------|------------|------|
| 危险点在Controller中 | 1层 | 直接检查参数来源 |
| 危险点在Service中 | 2层 | Controller→Service→危险点 |
| 危险点在DAO/Repository中 | 3层 | Controller→Service→DAO→危险点 |
| 危险点在工具类/Delegate中 | 3层+ | 必须追踪到输入源或硬编码常量 |

## 追踪结果记录格式

每条finding必须记录完整调用链：

```
输入源: LogicCommonServiceImpl.queryProgressInfo(@RequestParam String processId)
  → ProgressInfoComponent.getProgressInfo(processId)
    → [危险操作] processId未校验直接使用
```

如果追踪不完整，必须标注"缺失关键源码"及具体缺失环节。

## 追踪判断规则

- 追踪到输入源且参数用户可控 → 标记"用户可控"
- 追踪到硬编码常量/枚举/配置 → 标记"不可控"
- 追踪2层后仍无法确定来源 → 标记"缺失关键源码"，**不得直接判误报**
- 追踪到服务间调用 → 标记为前置条件或降级因素，不是自动的误报证明

## 传输链路追踪

当调用链涉及网络通信时，必须追踪传输链路安全：

1. 识别调用链中的网络通信节点（HTTP请求、WebSocket连接、RPC调用等）
2. 检查通信协议（HTTP vs HTTPS, WS vs WSS）
3. 检查SSL/TLS证书验证状态（verify参数、ssl配置）
4. 检查代理配置（HTTP_PROXY、系统代理、自定义代理）
5. 检查传输的敏感数据类型（凭据、Token、个人信息等）
6. 记录传输链路到阶段7的传输链路清单

**传输链路追踪结果格式**：

```
调用链: Controller.method(param) → Service.method(param) → [HTTP] http://api.example.com/endpoint
传输链路: HTTPS, verify=False, 传输数据: authToken + 请求载荷
传输风险: SSL验证关闭, 代理可拦截明文流量
```

如果调用链不涉及网络通信，标注"不涉及网络传输"即可跳过传输链路追踪。

## 传输链路敏感数据反向追踪

当发现以下源码信号时，必须执行**敏感数据反向追踪**，不能只记录信号本身：

### 触发条件

1. `verify=False`/`ssl_verify=False`/`ignore_https_errors=True` — SSL验证关闭
2. `http://`/`ws://` — 明文协议URL（非localhost）
3. 远程配置API响应包含密钥/Token/密码字段

### 追踪步骤

**步骤1：识别HTTP客户端实例**
- 找到verify=False所在代码，识别对应的HTTP客户端（httpx.AsyncClient、requests.Session、aiohttp.ClientSession等）
- 记录客户端变量名和作用域

**步骤2：追踪该客户端的所有请求**
- Grep搜索该客户端变量名，找到所有使用该客户端发起请求的位置
- 对每个请求，记录：目标URL、HTTP方法、请求头（特别是Authorization/Cookie）、请求体字段

**步骤3：识别传输的敏感数据**
- 对每个请求，评估传输数据中是否包含：
  - 认证凭据（API Key、Bearer Token、密码）
  - 会话标识（Cookie、CSRF Token、Session ID）
  - 个人信息（用户ID、邮箱、手机号）
  - 业务敏感数据（配置密钥、私钥、内部URL）

**步骤4：评估拦截影响**
- 如果该请求被拦截，攻击者获得什么？
- 获得的凭据是否可用于横向攻击其他系统？

### 追踪结果格式

```
SSL验证关闭点: idaas_client.py:177 — httpx.AsyncClient(verify=self.ssl_verify_enable)
  → 客户端实例: self._client
  → 请求1: auth_flow.py:256 — POST /oauth2/token, 传输: mtoken + refreshToken
  → 请求2: auth_flow.py:334 — GET /userinfo, 传输: Cookie + Authorization
  → 请求3: client.py:39 — GET /api/config, 传输: Authorization → 响应含secret_key
敏感数据汇总: mtoken、refreshToken、Cookie、secret_key
拦截影响: Token泄露可冒充用户身份；secret_key泄露可读写Langfuse数据
```

## API响应敏感数据追踪

当发现远程配置API或认证API时，必须追踪API响应中的敏感数据字段：

### 追踪步骤

1. 识别API响应的数据模型（Pydantic Model、dataclass、dict字段）
2. 检查响应中是否包含密钥/Token/密码字段
3. 追踪这些字段后续如何使用：
   - 是否作为HTTP请求的认证信息（Authorization头、Cookie）
   - 是否作为SDK初始化参数（如Langfuse SDK的secret_key）
   - 是否存储到本地文件或环境变量
4. 评估：如果API响应被拦截（因verify=False），攻击者直接获取这些敏感数据

### 追踪结果格式

```
API端点: GET /api/config (client.py:39)
  → 响应模型: RemoteConfig (models.py:14)
    → 敏感字段: langfuse_secret_key
      → 使用链: provider.py:413 → LangfuseTelemetryProvider.__init__ → Langfuse SDK
      → 传输链路: HTTP明文(HDP_LANGFUSE_HOST=http://) + verify=False
      → 拦截影响: 直接获取secret_key，无需分析SDK调用链
```