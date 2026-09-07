# 轻量扫描索引

关键词仅发现候选，不证明漏洞或防护。先文本搜索，再沿入口/实现/配置/数据流核验；逐文件类型分片处理截断，禁止只读前 N 条后声称全量完成。Java/Spring/Jalor 为正式范围，关联其他语言需记录实际覆盖局限。

| 类型 | 搜索范围 | 关键词/结构 | 核查重点与子 Skill |
|---|---|---|---|
| SQL注入 | Java/XML/SQL | ${、last/apply/inSql、Statement、JdbcTemplate、orderBy | 值与标识符分别追踪；`skill/SQL注入/skill.md` |
| XSS | Java/模板/关联前端 | v-html、innerHTML、th:utext、dangerouslySetInnerHTML | 当前渲染上下文与存储链；`skill/XSS/skill.md` |
| SSRF | Java/配置 | RestTemplate、WebClient、Feign、URL、HttpClient、callback | 实际目标控制、解析及重定向；`skill/SSRF/skill.md` |
| 反序列化 | Java/构建/配置 | ObjectInputStream、readObject、Fastjson、autoType、Jackson、XStream、Kryo | 版本、类型选择、过滤配置；`skill/反序列化/skill.md` |
| 路径穿越 | Java | File、Paths、Files、MultipartFile、ZipEntry、getOriginalFilename | 实际文件操作与边界；`skill/路径穿越/skill.md` |
| 命令注入 | Java | Runtime.exec、ProcessBuilder、sh -c、cmd /c、PowerShell | shell/选项/程序分别检查；`skill/命令注入/skill.md` |
| 权限控制 | Java/XML/配置 | permitAll、PreAuthorize、JalorOperation、DataRightCheck、findById、updateById、deleteById | 读取和写入都审，注解非结论；`skill/权限控制/skill.md` |
| XXE | Java | DocumentBuilderFactory、SAXParserFactory、XMLInputFactory、SAXReader、TransformerFactory、SchemaFactory | 确切解析实例及外部能力；`skill/XXE/skill.md` |
| 表达式注入 | Java/XML/配置 | SpelExpressionParser、parseExpression、Ognl、MVEL、JEXL、Aviator | 表达式文本与变量值分开；`skill/表达式注入/skill.md` |
| 不安全反射 | Java | Class.forName、loadClass、invoke、newInstance、setAccessible | 目标与成员能力；`skill/不安全反射/skill.md` |
| 敏感信息写入日志 | Java/日志配置 | logger、log、password、token、secret、Authorization | 参数实际值、序列化与脱敏；`skill/敏感信息写入日志/skill.md` |
| 硬编码 | 源码/配置/构建 | password、secret、api_key、private_key、AKIA、jdbc | 真实值、回退配置、打包使用；`skill/硬编码/skill.md` |
| 网络安全配置 | Java/部署/关联客户端 | http://、ws://、trust_all、check_hostname、verify=False、cors、allowCredentials、0.0.0.0 | 请求及响应敏感数据，实际 TLS/代理/浏览器行为；`skill/网络安全配置/skill.md` |
| CSV注入 | Java/导出 | CSVPrinter、CsvWriter、writeNext、text/csv、export | 实际单元格和消费方式；`skill/CSV注入/skill.md` |
| 弱随机数 | Java | Random、Math.random、ThreadLocalRandom、RandomStringUtils | 安全用途和实际随机源；`skill/弱随机数/skill.md` |
| 资源消耗 | Java/配置 | readAllBytes、toByteArray、upload、decompress、ZipInputStream、循环/递归 | 总量、并发、放大及取消；`skill/资源消耗/skill.md` |
| 输入校验 | Java/路由 | RequestParam、RequestBody、getParameter、MQ/导入字段 | 明确安全不变量，具体类型优先；`skill/输入校验/skill.md` |
| 供应链与签名校验缺失 | Java/构建/关联下载执行端 | upload、publish、download、install、verify_signature、checksum、sha256 | 攻击者影响、可信发布、实际字节与执行；`skill/供应链与签名校验缺失/skill.md` |

低风险线索只改变审查顺序，不自动排除。测试目录需核验打包/引用，配置需核验可修改主体和生效条件，框架防护需读取实现。回环地址不全局排除，查询接口不视为天然安全，服务间输入和存储数据继续追踪。

新入口或不支持框架出现时补充结构检查并记录覆盖缺口；没有关键词命中不等于不存在该类问题。
