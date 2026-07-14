# 扫描索引

本文件仅用于候选发现。最终判定需要候选排序、证据闭合模式，以及P0/P1候选对应的全量子Skill。

## 四层候选发现

按以下顺序组合使用；关键词命中只创建候选，不作为最终证据。

1. **文本层**：按本文件关键词分目录、分文件类型搜索，处理截断。
2. **结构层**：从路由/消息消费者/导入器到方法参数，再从危险API反向找调用者；XML Mapper、模板、配置项按结构读取。
3. **配置与依赖层**：核验构建依赖、运行profile、网关、安全链、HTTP客户端和部署清单，避免把未生效配置当事实。
4. **数据流层**：对P0/P1将Source、传播、Sink、防护和仓边界串联；无法串联时记录缺失环节。

项目语言或框架不在索引覆盖范围时，先扩展对应四层规则，再声明覆盖局限性；不得以“无关键词命中”证明安全。

## 索引格式

```
漏洞类型:
搜索文件:
关键词:
高风险上下文:
低风险上下文:
加载子Skill:
```

## SQL注入

```
搜索文件: *.java, *.xml, *.sql
关键词: ${, .last(, .apply(, .inSql(, orderBy, groupBy, Statement, createStatement, JdbcTemplate
高风险上下文: 外部输入到达SQL结构/值构造；MyBatis ${}；动态表名/列名/排序/条件
低风险上下文: 枚举/Map白名单；固定字面量；参数化#{}/PreparedStatement用于值；测试/演示代码
加载子Skill: skill/SQL注入
```

## XSS

```
搜索文件: *.vue, *.js, *.jsx, *.ts, *.tsx, *.html, *.java
关键词: v-html, innerHTML, outerHTML, dangerouslySetInnerHTML, th:utext, rawHtml, html()
高风险上下文: 用户可控内容到达HTML/属性/JS/URL/CSS渲染上下文
低风险上下文: 固定内容；可信模板；上下文适当的编码/过滤
加载子Skill: skill/XSS
```

## SSRF

```
搜索文件: *.java, *.yml, *.yaml, *.properties
关键词: RestTemplate, WebClient, URL(, URI(, openConnection, HttpClient, OkHttp, Feign, proxy, callbackUrl
高风险上下文: 用户可控URL/主机/路径/回调到达服务端请求
低风险上下文: 固定服务地址；服务发现名称；强协议/主机/IP校验
加载子Skill: skill/SSRF
```

## 反序列化

```
搜索文件: *.java, pom.xml, build.gradle
关键词: ObjectInputStream, readObject, XStream, fastjson, autoType, enableDefaultTyping, jackson, YAMLFactory
高风险上下文: 不可信字节/文本进入反序列化器；存在漏洞依赖/配置
低风险上下文: 可信内部数据；安全配置；无用户可控输入
加载子Skill: skill/反序列化
```

## 路径穿越

```
搜索文件: *.java
关键词: new File(, Paths.get, Path.of, FileInputStream, FileOutputStream, Files.copy, MultipartFile, ZipEntry, getOriginalFilename
高风险上下文: 用户可控文件名/路径/压缩条目到达文件系统操作
低风险上下文: 服务端生成文件名；规范化基目录校验；固定白名单
加载子Skill: skill/路径穿越
```

## 命令注入

```
搜索文件: *.java
关键词: Runtime.getRuntime().exec, ProcessBuilder, sh -c, cmd /c, powershell, bash, exec(
高风险上下文: 用户可控命令或参数到达shell/可执行程序
低风险上下文: 固定可执行程序；分离参数；枚举约束输入
加载子Skill: skill/命令注入
```

## 权限控制

```
搜索文件: *.java, *.xml, *.yml, *.properties
关键词: permitAll, anonymous, @PreAuthorize, @RequiresPermissions, hasRole, antMatchers, requestMatchers, findById, updateById, deleteById
高风险上下文: 外部对象ID到达读/更新/删除操作，无所有权/租户校验
低风险上下文: 查询受当前用户/租户约束；显式所有权校验
加载子Skill: skill/权限控制
```

## XXE

```
搜索文件: *.java
关键词: DocumentBuilderFactory, SAXParserFactory, XMLInputFactory, SAXReader, TransformerFactory, SchemaFactory
高风险上下文: 用户可控XML被解析，外部实体/Feature启用或未知
低风险上下文: DOCTYPE/外部实体在该确切解析器上已禁用
加载子Skill: skill/XXE
```

## 表达式注入

```
搜索文件: *.java, *.xml, *.yml
关键词: SpelExpressionParser, parseExpression, getValue, Ognl.getValue, MVEL, JexlExpression, AviatorEvaluator
高风险上下文: 用户可控表达式文本被求值
低风险上下文: 注解/静态表达式；后端固定模板
加载子Skill: skill/表达式注入
```

## 不安全反射

```
搜索文件: *.java
关键词: Class.forName, loadClass, getMethod, invoke, setAccessible(true), newInstance
高风险上下文: 用户可控类/方法名到达反射调用，目标是危险类
低风险上下文: 固定类名；强白名单映射
加载子Skill: skill/不安全反射
```

## 敏感信息写入日志

```
搜索文件: *.java, *.kt, *.groovy
关键词: log.info, log.debug, log.warn, log.error, logger., password, passwd, token, secret, authorization, idcard, mobile
高风险上下文: 敏感用户/凭据/令牌数据在生产路径中被记录
低风险上下文: 已脱敏/遮盖值；仅测试；非敏感trace id
加载子Skill: skill/敏感信息写入日志
```

## 硬编码

```
搜索文件: *.java, *.yml, *.yaml, *.properties, *.js, *.ts, Dockerfile, *.xml
关键词: password=, passwd=, secret, token, api_key, accessKey, AKIA, private_key, jdbc:
高风险上下文: 生产代码/配置包含实际凭据或私钥
低风险上下文: 环境变量/配置中心占位符；测试夹具；文档示例
加载子Skill: skill/硬编码
```

## 网络安全配置

```
搜索文件: *.java, *.yml, *.yaml, *.properties, Dockerfile, *.conf, *.py, *.ts, *.js, *.env
关键词: cors, allowedOrigins, allowCredentials, 0.0.0.0, management.endpoints, csrf.disable, X-Frame-Options, Content-Security-Policy, verify=False, verify_ssl, ssl_verify, ignore_https_errors, InsecureRequestWarning, ssl._create_unverified_context, check_hostname=False, ws://, HTTP_PROXY, HTTPS_PROXY, NO_PROXY, trust_all, disable_ssl, CERT_NONE
高风险上下文: 不安全配置适用于暴露的部署路径；SSL验证关闭导致传输链路可被拦截；明文协议传输敏感数据
低风险上下文: 仅本地Profile；部署边界阻止暴露；开发环境配置且有环境隔离
加载子Skill: skill/网络安全配置
```

## 明文协议传输敏感数据

```
搜索文件: *.py, *.ts, *.js, *.java, *.yml, *.yaml, *.properties, *.env
关键词: http://, ws://
高风险上下文: http://或ws:// URL传输凭据、Token、密码、API Key等敏感数据；非localhost的HTTP URL
低风险上下文: localhost/127.0.0.1回环通信且无代理配置支持；传输数据不包含敏感信息
加载子Skill: skill/网络安全配置
注意: 搜索http://时排除localhost/127.0.0.1，聚焦外部通信。必须追踪该URL传输什么数据
```

## SSL验证关闭的敏感数据传输

```
搜索文件: *.py, *.ts, *.js, *.java
关键词: verify=False, verify_ssl=False, ssl_verify=False, ignore_https_errors=True, ssl._create_unverified_context, CERT_NONE, check_hostname=False
高风险上下文: SSL验证关闭的HTTP客户端传输凭据、Token、密码、API Key等敏感数据
低风险上下文: 仅测试代码；开发环境且有环境隔离；传输数据不包含敏感信息
加载子Skill: skill/网络安全配置
注意: 发现verify=False后必须反向追踪——该HTTP客户端传输什么敏感数据？不能只记录"SSL验证关闭"而不追踪传输内容
```

## API响应敏感数据

```
搜索文件: *.py, *.ts, *.js, *.java
关键词: secret_key, secretKey, api_key, apiKey, access_token, accessToken, password, passwd, credential, private_key, token
高风险上下文: 远程配置API或认证API的响应中包含密钥/Token/密码字段，且后续通过不安全传输链路使用
低风险上下文: 响应数据仅在内存中使用且不通过网络传输；响应通过安全传输链路获取
加载子Skill: skill/网络安全配置
注意: 这是"数据源追踪"——不仅追踪用户输入→Sink，还要追踪API响应→敏感数据→后续传输。发现API返回敏感字段时，必须追踪该字段后续是否通过不安全链路传输
```

## CSV注入

```
搜索文件: *.java, *.js, *.ts
关键词: CsvWriter, CSVPrinter, writeNext, text/csv, Content-Disposition, export
高风险上下文: 用户可控单元格值导出时未中和公式前缀字符
低风险上下文: 值已加前缀/转义处理公式字符
加载子Skill: skill/CSV注入
```

## 弱随机数

```
搜索文件: *.java, *.js, *.ts
关键词: new Random(), Math.random, RandomStringUtils, ThreadLocalRandom
高风险上下文: 随机数用于令牌、密码重置、验证码、加密、签名
低风险上下文: UI、采样、非安全业务展示
加载子Skill: skill/弱随机数
```

## 资源消耗

```
搜索文件: *.java, *.js, *.ts
关键词: readAllBytes, toByteArray, while(true), for(;;), recursion, unbounded, upload, ZipInputStream, decompress
高风险上下文: 用户可控大小/循环/解压缩无限制
低风险上下文: 显式大小/时间/速率/深度限制
加载子Skill: skill/资源消耗
```

## 输入校验

```
搜索文件: *.java, *.js, *.ts, *.vue
关键词: @RequestParam, @RequestBody, request.getParameter, JSON.parse, params, query
高风险上下文: 外部输入影响安全敏感操作，但无更具体的CWE适用
低风险上下文: 已有具体漏洞类型适用；强Schema/业务校验
加载子Skill: skill/输入校验
```

## 供应链/安装包签名校验缺失（第18种漏洞类型）

```
搜索文件: *.java, *.py, *.js, *.ts
关键词:
  服务端: uploadNewVersion, addVersion, uploadFile, MultipartFile, Attachment, file.upload, upload_artifact, publish, deploy, release
  客户端: subprocess.Popen, exec, dpkg, rpm, pip.install, npm.install, check_version, check_update, download_and_install, auto_update, auto_upgrade, silent_install, /S, --silent
  签名校验: verify_signature, check_signature, code_sign, authenticode, gpg.verify, sha256, md5, checksum, hash_verify, integrity_check, sign.verify
高风险上下文:
  1. 服务端接受文件上传（安装包/插件/技能/配置）但无签名校验、无文件类型校验、无完整性校验
  2. 客户端下载文件后直接执行（subprocess.Popen/exec/dpkg/pip install）但无签名验证、无MD5/SHA256校验
  3. 更新/升级/分发通道：服务端提供下载→客户端下载并执行，中间无签名校验
  4. 插件/技能/扩展市场：用户上传→其他用户下载执行，无签名校验
低风险上下文:
  1. 上传时校验数字签名（Authenticode/GPG/code signing）
  2. 下载后验证签名或MD5/SHA256校验和
  3. 仅分发内部签名包，客户端拒绝未签名包
  4. 测试/演示环境的上传接口
加载子Skill: skill/供应链与签名校验缺失
注意: 这是跨代码仓高发漏洞——上传接口在代码仓A，执行逻辑在代码仓B，单仓扫描容易遗漏。发现上传接口时必须追踪：谁下载？下载后是否执行？执行前是否校验签名？
```

## 命令注入（Python补充规则）

```
搜索文件: *.py
关键词: subprocess.Popen, subprocess.run, subprocess.call, os.system, os.popen, exec(, eval(
高风险上下文（补充）:
  1. subprocess.Popen/Run/Call执行变量路径（如下载的安装包路径、用户指定的可执行文件路径）
  2. 执行从网络下载的文件（下载→写入磁盘→执行），无论路径是否用户可控
  3. dpkg -i, rpm -i, pip install 等包管理命令执行下载的包文件
低风险上下文:
  1. 执行硬编码的固定路径命令
  2. 参数完全由枚举/白名单控制
  3. 在沙箱/容器中执行
注意: "执行下载的文件"是命令注入的特殊变体——即使路径不含用户输入，文件内容本身可能被篡改（供应链攻击）。必须追踪文件来源
```

## 权限控制（补充规则）

```
搜索文件: *.java, *.py
关键词（补充）:
  Java: @JalorOperation, @JalorResource, @DataRightCheck, RequestConstants.IMPORT, RequestConstants.CREATE, RequestConstants.DELETE, RequestConstants.UPDATE
  Python: @app.route, @router.post, @router.put, @router.delete, APIRouter, FastAPI路由装饰器
高风险上下文（补充）:
  1. @JalorOperation(code=IMPORT/CREATE/DELETE/UPDATE) 但无 @DataRightCheck 注解——操作类接口缺少数据权限校验
  2. FastAPI路由无认证中间件（无Depends(get_current_user)等）
  3. 文件上传/发布/删除接口无权限校验注解
低风险上下文:
  1. 有@DataRightCheck或等效权限注解
  2. 有FastAPI认证依赖注入
  3. 接口仅查询/读取操作
注意: @JalorOperation仅声明操作类型，不负责权限校验。需要额外检查是否有@DataRightCheck等权限注解
