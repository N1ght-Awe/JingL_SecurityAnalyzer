使用证明模式编写简洁、可审查的漏洞证明。默认基于源码证据，不依赖运行时攻击执行。

## 模式格式

- 编号: 唯一标识
- 名称: 模式名称
- 漏洞类型: CWE分类
- 必要证据: 确认漏洞所需的源码证据
- 误报证据: 可排除漏洞的证据
- 利用前置条件: 利用所需条件

## SQL注入：MyBatis ORDER BY `${}`

- 编号: sql-injection.mybatis-order-by-dollar
- 名称: MyBatis ORDER BY标识符注入
- 漏洞类型: SQL注入
- 必要证据:
  - 用户可控排序字段到达Mapper，ORDER BY位置使用${}
  - 无枚举/Map/强白名单适用于该参数
- 误报证据:
  - 参数仅由后端枚举或固定Map生成
  - 强白名单将外部名称映射到固定SQL标识符
- 利用前置条件:
  - 攻击者可访问端点并影响排序参数

## SQL注入：MyBatis-Plus Wrapper动态方法

- 编号: sql-injection.mybatis-plus-wrapper
- 名称: MyBatis-Plus Wrapper方法注入
- 漏洞类型: SQL注入
- 必要证据:
  - 用户可控输入到达.last()/.apply()/.inSql()/.exists()等Wrapper方法
  - 无枚举/白名单约束
- 误报证据:
  - 参数为后端固定值或强白名单映射
- 利用前置条件:
  - 攻击者可访问端点并影响Wrapper方法参数

## SSRF：用户可控URL客户端

- 编号: ssrf.user-controlled-http-client
- 名称: 用户可控URL到达服务端HTTP客户端
- 漏洞类型: SSRF
- 必要证据:
  - 外部可控URL到达RestTemplate/WebClient/URL/openConnection/HttpClient/OkHttp
  - 协议、主机/IP、DNS和重定向校验缺失或弱
- 误报证据:
  - 目标为固定服务配置，强白名单和解析后校验适用
- 利用前置条件:
  - 攻击者可提交URL类字段，服务端网络可到达目标资源

## 路径穿越：用户文件名到文件API

- 编号: path-traversal.user-filename-file-api
- 名称: 用户可控文件名到达文件系统API
- 漏洞类型: 路径穿越
- 必要证据:
  - 文件名/路径来自请求/上传/消息/数据库二次输入，到达File/Path/压缩解压API
  - 规范化基目录包含校验缺失
- 误报证据:
  - 文件名由服务端生成，或规范化路径检查在基目录之下
- 利用前置条件:
  - 攻击者可控制文件名/路径或压缩条目名

## 路径穿越：ZipSlip

- 编号: path-traversal.zipslip
- 名称: ZIP解压文件名穿越
- 漏洞类型: 路径穿越
- 必要证据:
  - ZIP解压使用压缩包内文件名拼接路径，未做规范化基目录校验
- 误报证据:
  - 解压前校验条目路径在目标目录之下，或文件名重命名为服务端生成值
- 利用前置条件:
  - 攻击者可上传/提供恶意ZIP文件

## 权限控制：IDOR

- 编号: access-control.idor-missing-ownership
- 名称: 对象标识符缺少所有权校验
- 漏洞类型: 权限控制
- 必要证据:
  - 外部ID/对象键到达数据访问或状态变更操作，所有权/租户校验缺失
- 误报证据:
  - 查询受当前用户/租户约束，或操作前服务端检查所有权
- 利用前置条件:
  - 攻击者拥有账户且可猜测/获取其他对象标识符

## XSS：前端危险渲染

- 编号: xss.frontend-dangerous-render
- 名称: 用户可控内容到达前端危险渲染
- 漏洞类型: XSS
- 必要证据:
  - 用户可控内容到达v-html/innerHTML/dangerouslySetInnerHTML等渲染Sink
  - 无上下文适当的编码或过滤
- 误报证据:
  - 内容为固定可信数据，或上下文适当的编码/过滤已应用
- 利用前置条件:
  - 攻击者可控制渲染内容

## 命令注入：Shell执行器

- 编号: command-injection.shell-executor
- 名称: 用户可控输入到达Shell执行器
- 漏洞类型: 命令注入
- 必要证据:
  - 用户可控命令/参数到达sh -c/cmd /c，或以单字符串形式传入ProcessBuilder
- 误报证据:
  - 固定可执行程序+分离参数数组，或用户输入受后端枚举约束
- 利用前置条件:
  - 攻击者可访问端点并影响命令或参数

## 反序列化：Fastjson autoType

- 编号: deserialization.fastjson-autotype
- 名称: Fastjson autoType启用
- 漏洞类型: 反序列化
- 必要证据:
  - Fastjson启用autoType或版本低于安全版本，不可信数据到达parse/parseObject
  - 无autoType安全配置或版本存在已知CVE
- 误报证据:
  - autoType显式禁用，或非漏洞版本且安全配置生效
- 利用前置条件:
  - 攻击者可控制JSON输入内容

## 表达式注入：SpEL动态求值

- 编号: expression-injection.spel-dynamic
- 名称: 用户可控SpEL表达式动态求值
- 漏洞类型: 表达式注入
- 必要证据:
  - 表达式文本来自运行时外部输入，使用StandardEvaluationContext
- 误报证据:
  - 表达式为注解字面量属性/final常量/硬编码字符串，或使用SimpleEvaluationContext
- 利用前置条件:
  - 攻击者可控制表达式文本内容

## 不安全反射：Class.forName用户可控

- 编号: unsafe-reflection.class-forname
- 名称: Class.forName参数用户可控
- 漏洞类型: 不安全反射
- 必要证据:
  - Class.forName/loadClass参数来自用户可控输入，反射目标为危险类
- 误报证据:
  - 类名为固定白名单映射，或反射目标为安全类
- 利用前置条件:
  - 攻击者可控制类名字符串

## XXE：XML解析器未禁用外部实体

- 编号: xxe.parser-external-entities-enabled
- 名称: XML解析器未禁用外部实体
- 漏洞类型: XXE
- 必要证据:
  - 用户可控XML到达解析器，未设置disallow-doctype-decl=true或等效安全配置
- 误报证据:
  - 该解析器实例已禁用外部实体，或XML内容为固定可信数据
- 利用前置条件:
  - 攻击者可控制XML输入内容

## 敏感信息写入日志

- 编号: sensitive-log.credential-in-log
- 名称: 凭据/敏感数据写入日志
- 漏洞类型: 敏感信息写入日志
- 必要证据:
  - 日志输出包含强敏感信息（password/secret/token/key等），在生产代码路径中
- 误报证据:
  - 值已脱敏/遮盖，或仅测试代码，或非敏感trace_id等
- 利用前置条件:
  - 攻击者可访问日志文件或日志系统

## 硬编码密钥

- 编号: hardcoded-secret.credential-in-code
- 名称: 代码/配置中硬编码凭据
- 漏洞类型: 硬编码
- 必要证据:
  - 生产代码/配置包含明文凭据（password/secret/key/AK等），非环境变量/配置中心占位符
- 误报证据:
  - 值为环境变量引用(${VAR})/配置中心占位符，或位于src/test下
- 利用前置条件:
  - 攻击者可获取源码或配置文件

## 网络安全配置：不安全配置暴露

- 编号: network-security-config.insecure-exposure
- 名称: 不安全安全配置适用于暴露路径
- 漏洞类型: 网络安全配置
- 必要证据:
  - 不安全配置（CORS */0.0.0.0/CSRF禁用等）存在且适用于暴露部署路径
- 误报证据:
  - 配置仅在本地Profile中，或部署边界阻止外部访问
- 利用前置条件:
  - 攻击者可从外部访问受影响端点

## CSV注入：导出数据未中和公式前缀

- 编号: csv-injection.formula-prefix
- 名称: 导出数据未中和公式前缀字符
- 漏洞类型: CSV注入
- 必要证据:
  - 用户可控数据写入导出文件，未对=、+、-、@等危险前缀字符做中和处理
- 误报证据:
  - 值已加单引号/Tab前缀，或使用自定义Converter，或单元格格式设为文本
- 利用前置条件:
  - 攻击者可控制导出数据内容，用户用Excel/WPS打开

## 弱随机数：安全场景使用不安全随机

- 编号: weak-random.insecure-for-security
- 名称: 安全敏感场景使用不安全随机数
- 漏洞类型: 弱随机数
- 必要证据:
  - 使用java.util.Random/Math.random等不安全随机源，用途为安全敏感场景
- 误报证据:
  - 用途为非安全场景（UI/采样/业务展示），或安全敏感值由SecureRandom生成
- 利用前置条件:
  - 攻击者可预测随机数输出

## 资源消耗：无限制操作

- 编号: resource-exhaustion.unbounded-operation
- 名称: 用户可控无限制资源消耗操作
- 漏洞类型: 资源消耗
- 必要证据:
  - 用户可控大小/循环/解压缩操作，无显式大小/时间/速率/深度限制
- 误报证据:
  - 显式限制存在且合理，或操作受框架默认限制约束
- 利用前置条件:
  - 攻击者可控制操作规模

## 输入校验：缺失输入校验

- 编号: input-validation.missing-validation
- 名称: 安全敏感操作缺少输入校验
- 漏洞类型: 输入校验
- 必要证据:
  - 外部输入影响安全敏感操作，无更具体CWE适用，缺少类型+范围+白名单强校验
- 误报证据:
  - 已有具体漏洞类型适用（应按具体类型分析），或强Schema/业务校验存在
- 利用前置条件:
  - 攻击者可控制输入内容和格式

## 传输链路拦截：SSL验证关闭

- 编号: transport-interception.ssl-verify-disabled
- 名称: SSL/TLS证书验证关闭导致传输链路可被中间人拦截
- 漏洞类型: 网络安全配置
- 必要证据:
  - 代码中存在verify=False/ignore_https_errors/ssl_verify=False等配置
  - 该配置影响包含敏感数据的网络通信
  - 通信目标为非本地地址或本地服务可被代理转发
- 误报证据:
  - 配置仅在开发环境生效且有环境隔离
  - 通信不包含敏感数据
  - 配置被运行时覆盖为True
- 利用前置条件:
  - 攻击者可在网络路径上部署代理（如Burp Suite）
  - 应用接受代理的自签名证书

## 传输链路拦截：明文协议传输敏感数据

- 编号: transport-interception.plaintext-sensitive-data
- 名称: 敏感数据通过明文协议传输可被网络嗅探拦截
- 漏洞类型: 网络安全配置
- 必要证据:
  - 代码中使用http://或ws://传输敏感数据（凭据、Token、个人信息）
  - 通信不在本地回环地址或本地回环但可被代理转发
- 误报证据:
  - 本地回环通信且无代理配置支持
  - 传输数据不包含敏感信息
  - 开发态代理且有环境隔离
- 利用前置条件:
  - 攻击者可在网络路径上嗅探流量（Wireshark/tcpdump）
  - 或应用配置了系统代理（HTTP_PROXY）

## 传输链路拦截：CORS滥用

- 编号: transport-interception.cors-abuse
- 名称: CORS配置滥用允许跨域凭据窃取
- 漏洞类型: 网络安全配置
- 必要证据:
  - allow_origins=["*"]或反射型CORS + allow_credentials=True
  - 接口返回敏感数据
  - 接口无其他认证保护或认证基于Cookie
- 误报证据:
  - CORS仅限具体可信来源
  - 接口不返回敏感数据
  - 认证不依赖Cookie（如Bearer Token）
- 利用前置条件:
  - 攻击者可诱导用户访问恶意页面
  - 用户已登录目标应用

## 敏感数据明文传输：HTTP协议传输凭据

- 编号: sensitive-data-transport.plaintext-http
- 名称: 敏感数据通过HTTP明文协议传输
- 漏洞类型: 网络安全配置
- 必要证据:
  - 代码中使用http://或ws://传输凭据、Token、密码、API Key等敏感数据
  - 通信目标为非本地回环地址或本地回环但可被代理转发
  - 敏感数据类型明确（API Key、密码、Token、私钥等）
- 误报证据:
  - 本地回环通信且无代理配置支持
  - 传输数据不包含敏感信息
  - 开发态代理且有环境隔离
- 利用前置条件:
  - 攻击者可在网络路径上嗅探流量（Wireshark/tcpdump）
  - 或应用配置了系统代理（HTTP_PROXY）

## 敏感数据传输：SSL验证关闭+凭据传输

- 编号: sensitive-data-transport.ssl-disabled-with-credentials
- 名称: SSL验证关闭的HTTP客户端传输敏感凭据
- 漏洞类型: 网络安全配置
- 必要证据:
  - HTTP客户端配置verify=False/ssl_verify=False/ignore_https_errors=True
  - 该客户端的请求中携带认证凭据（Authorization头、Cookie、密码字段）
  - 凭据类型明确（API Key、Bearer Token、用户密码、Session ID等）
  - 拦截后攻击者可获取的凭据及其影响已评估
- 误报证据:
  - 传输数据不包含敏感信息
  - 仅测试代码且无生产引用
  - 开发环境且有环境隔离机制
- 利用前置条件:
  - 攻击者可在网络路径上部署代理（如Burp Suite）
  - 应用接受代理的自签名证书（因verify=False）

## API响应敏感数据：远程配置下发密钥

- 编号: sensitive-data-transport.api-response-credentials
- 名称: 远程配置API响应中包含密钥/Token并通过不安全链路传输
- 漏洞类型: 网络安全配置
- 必要证据:
  - 远程配置API或认证API的响应数据模型中包含密钥/Token/密码字段
  - 该API通过SSL验证关闭的客户端调用或使用HTTP明文协议
  - 响应中的敏感字段后续被使用（SDK初始化、认证、存储等）
- 误报证据:
  - API通过安全传输链路调用（HTTPS + 证书验证启用）
  - 响应中不包含敏感字段
  - 敏感字段仅用于本地内存且不进一步传输
- 利用前置条件:
  - 攻击者可在网络路径上拦截API响应（因verify=False或HTTP明文）

## 供应链：上传到下载执行缺少可信校验

- 编号: supply-chain.upload-download-execute-without-verification
- 名称: 跨代码仓制品分发到执行缺少签名/可信完整性校验
- 漏洞类型: 供应链/签名校验缺失
- 必要证据:
  - 代码仓A中攻击者可影响制品、版本或下载元数据的上传/发布路径
  - 存储、下载接口或跨仓关联将该制品传递到代码仓B
  - 代码仓B在安装、加载或执行前未验证实际字节的可信签名，或哈希不来自独立可信通道
  - 上传者权限、签名校验、下载链路、执行点和仓边界均有源码/配置证据
- 误报证据:
  - 服务端或客户端在执行前强制验证可信发布者签名，失败即拒绝
  - 制品只用于数据处理且不被安装、加载或执行
- 利用前置条件:
  - 攻击者具有上传/发布权限，或可通过上游漏洞影响制品或元数据
