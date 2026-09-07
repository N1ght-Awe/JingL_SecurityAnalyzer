# 证明义务索引

按类型选择对应行，不加载教学案例。每项都受 proof-schema.md 八维、同路径反证和结论范围约束。未知信息写缺口；验证目标见 poc-generation.md。

| 模式 ID | 必须证明 |
|---|---|
| sql-injection.mybatis-order-by-dollar | 可控标识符到达实际 SQL 结构；同字段缺乏固定映射。值参数绑定不能保护拼接标识符。 |
| sql-injection.mybatis-plus-wrapper | 读取 Wrapper 最终 SQL 和参数绑定方式；区分实际结构拼接与安全绑定，不按方法名确认。 |
| ssrf.user-controlled-http-client | 可控目标突破既定请求边界；核验实际连接地址、重定向和解析时序；合法公开 URL 抓取不自动构成 SSRF。 |
| path-traversal.user-filename-file-api | 可控路径导致实际文件操作越过允许目录；核验路径组件、符号链接及检查与使用时序。 |
| path-traversal.zipslip | 压缩条目经真实解包写入基目录之外；检查绝对路径、符号链接和每条目的目标路径。 |
| access-control.idor-missing-ownership | 明确主体、资源归属、业务政策和真实授权链；他人数据读取也须审查。合法共享或管理员权限需具体政策证据。 |
| xss.frontend-dangerous-render | 可控值进入实际可执行渲染上下文；读取同上下文净化，单纯字符串展示不成立。 |
| command-injection.shell-executor | 证明用户影响实际执行语义；Java exec/ProcessBuilder 不因字符串形式自动调用 shell；分离参数仍检查选项和程序能力。 |
| deserialization.fastjson-autotype | 证明实际反序列化版本、配置、可控类型及危险行为；依赖命中或 autoType 字样不等于可利用 RCE。 |
| expression-injection.spel-dynamic | 可控表达式突破实际上下文能力边界；受限上下文的具体能力与可访问对象必须读取。 |
| unsafe-reflection.class-forname | 可控类/方法选择抵达危险能力；固定接口类型或包名前缀不自动证明目标安全。 |
| xxe.parser-external-entities-enabled | 不可信 XML 到达实际解析器且目标实体/外部访问能力生效；未知默认值不能当开启。 |
| sensitive-log.credential-in-log | 真实敏感值经当前生产日志/序列化/脱敏链可恢复；其他输出路径的注解不构成反证。 |
| hardcoded-secret.credential-in-code | 真实秘密以不应保存的方式暴露且有加载/使用依据；有效性未知单列，不自动归为缺失源码。 |
| network-security-config.insecure-exposure | 实际配置生效、暴露边界和具体影响闭合；内网绑定、安全头缺失都不是自动结论。 |
| csv-injection.formula-prefix | 实际导出和目标消费方式能解释不可信公式；引号、Tab/单引号前缀需验证消费/转存语义。 |
| weak-random.insecure-for-security | 弱随机来源抵达安全决策，结合熵、可观测性与尝试限制；非安全用途明确排除。 |
| resource-exhaustion.unbounded-operation | 可控输入导致无界或放大消耗且对应资源无有效上界；单次字节限制/线程池不等于全链限额。 |
| input-validation.missing-validation | 明确业务安全不变量及越过规则的真实后果；更具体类型优先，不泛报缺少校验。 |
| transport-interception.ssl-verify-disabled | 真实客户端验证配置和敏感流量闭合，并说明攻击者网络位置；代理装有受信证书不证明信任任意证书。 |
| transport-interception.plaintext-sensitive-data | 确切明文流包含敏感数据且存在相应网络暴露；按部署边界论证。 |
| transport-interception.cors-abuse | 实际浏览器允许不可信 origin 读取受保护响应；通配 origin 加 include 凭据本身不满足浏览器共享条件。 |
| sensitive-data-transport.plaintext-http | 与明文传输模式共用证明义务；同根因合并，不重复计数。 |
| sensitive-data-transport.ssl-disabled-with-credentials | 与 TLS 验证关闭模式共用证明义务；客户端实例、传输字段及生效配置需一致。 |
| sensitive-data-transport.api-response-credentials | 敏感响应已在不安全链路暴露即可证明该段泄露；后续仅存内存不能消除已发生的传输。 |
| supply-chain.upload-download-execute-without-verification | 攻击者可影响被信任执行的制品，上传/分发/实际字节/执行前可信校验逐环闭合；HTTPS或缺签名单点均不是结论。 |

权限审查补充：默认参数/空集合导致查询条件消失、批量资源部分未授权、查询返回他人数据、跨租户上下文可控均需沿实际策略验证。空结果不证明安全；测试数据不存在不等于权限限制。合法全局查询只有业务政策和主体权限共同支持时才排除。
