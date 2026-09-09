# HTTP 提取细节：绑定、网关与 Jalor

仅在 http-extraction.md 所述 HTTP 验证确有需要且路由/绑定较复杂时加载。本文件是补充，不改变主流程阶段，不另立报告字段。候选发现无需为所有命中提前生成完整请求。

## 入口与路径

- Spring：类/方法映射、HTTP 方法、headers/params/consumes/produces 条件；多条映射分别核对。
- JAX-RS/CXF/Jersey：资源注册、接口与实现的 @Path、HTTP 动词、@ApplicationPath/servlet mapping；同时检查实际绑定规则和接口注解，不只搜实现类。
- 分别记录外部网关路径和应用接收路径，沿 context-path、servlet path、rewrite/strip-prefix 等配置追踪。不是所有场景都把前缀相加。
- Jalor/WSF 可检查 OpenAPI basePath、x-wsf-urlPrefix、interface_list.properties 和运行过滤器配置，作为对应版本的拼接/重写证据；识别 basePath 已含的部分避免重复。白名单不是全量路由目录，未命中不单独证明 URL 错误。
- /services、/publicservices、ER/IR 和 permitAll 均只是当前安全链的线索。读取消费白名单的实际控制逻辑；通过一层不等于无需认证、任意登录用户有权限或其余层放行。

## 参数与请求体

沿路径/查询/Header/Cookie/form/multipart/实体参数分别映射；JAX-RS 不要求 @RequestBody，但不能把所有方法参数都当 JSON body。记录 Content-Type、必填/默认值、验证分组、继承、泛型及实际调用。

读取实际序列化器：字段/getter/构造器、JsonProperty/JsonAlias/JsonIgnore、命名策略、枚举、日期格式、自定义反序列化、对象身份/循环引用等。VO Java 字段名不一定是 HTTP 字段名；缺绑定实现留缺口，不能猜 url 自动映射 attachmentUrl。

只展开请求真正需要的嵌套结构，处理循环/深度边界；JSON 不含注释。缺 host、会话、对象 ID 或业务前置状态用明确待填项，不能称请求已可直接运行。使用用户授权环境的测试身份与归属明确的测试资源。

## 请求与结果记录

在 finding.exploitation 中保留方法、外部/内部路径及构造证据、头/参数/body、认证与对象政策、字段→代码绑定表、前置步骤、预期/实际响应及各自证据。HTTP 明细可以作为外部附件引用，不引入旧 exploitation_method、http_interface/http_poc 顶层契约。

预期响应读真实返回类型、序列化和异常处理，不按 ResponseVo 名称套固定 JSON；预期与实际分开。HTTP 200、没有403、创建成功等只能证明响应或操作发生；利用成功还需本应被禁止的效果成立。

重放时记录实际目标、身份、配置、原始结果与对照至 validation；未重放请求不产生 PASSED，也不扩展验证范围。完整系统是否启动遵循 poc-generation.md 的范围选择。
