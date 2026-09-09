# 输入源路由

漏洞扫描前必须使用本文件。先构建项目画像，再生成输入源扫描计划。

## 项目画像输入

存在时优先检查以下文件：

- `pom.xml`、`build.gradle`、`settings.gradle`
- `package.json`、lockfiles
- `application.yml`、`application.properties`、`bootstrap.yml`
- Docker、compose、Kubernetes清单
- Spring Security、Shiro、Filter、拦截器、网关配置
- Nacos、Apollo、配置中心引用

记录每条画像事实：

```
项目:
来源文件:
作用范围:
置信度:
全局适用性:
局限性:
```

全局画像事实仅作上下文参考，不能作为具体finding的误报证明，除非映射到确切的代码路径。

## 输入源激活规则

根据项目证据激活扫描：

| 项目证据 | 启用的输入源 |
|---------|------------|
| `spring-boot-starter-web`、MVC注解 | `@RestController`、`@Controller`、映射注解、`HttpServletRequest`、请求头、Cookie、请求体 |
| CXF/Jersey/JAX-RS 依赖、资源注册、`@Path` | 资源接口及实现、`@GET/@POST`、Path/Query/Header/Cookie/Form 参数、实体 body；追踪实际注册和绑定 |
| `spring-boot-starter-webflux` | 响应式Controller、`RouterFunction`、`ServerRequest` |
| `MultipartFile`、上传配置 | 文件上传内容、原始文件名、导入管道 |
| `spring-kafka` | `@KafkaListener`、`ConsumerRecord`、消息载荷 |
| RabbitMQ依赖 | `@RabbitListener`、`Message`载荷 |
| RocketMQ依赖 | `@RocketMQMessageListener`、`onMessage` |
| Dubbo依赖/配置 | `@DubboService`、服务XML、RPC方法参数 |
| gRPC依赖 | 生成的服务实现、请求消息 |
| Quartz、XXL-JOB、`@Scheduled` | 定时任务参数、Handler execute、调度器控制的输入 |
| WebSocket依赖 | `@MessageMapping`、`WebSocketHandler`、`TextMessage` |
| GraphQL依赖 | `@QueryMapping`、`@MutationMapping`、GraphQL解析器 |
| CSV/Excel/XML/JSON解析器 | 导入文件内容及解析字段 |
| ORM/数据访问层 | 数据库二次注入（存储数据后续到达Sink） |

## 资产枚举与前端复核

先枚举指定根目录的仓库、构建模块和兄弟目录，再统计实际源码；不把每个嵌套目录当独立仓库。对候选模块检查 Java/构建文件、package.json、Vue/JS/TS/JSX/TSX、HTML/模板、部署与网关配置。排除依赖/生成物须留路径与理由，不能排除实际业务模板。搜索失败、权限错误、截断和未提供不记成 0。

package.json 或 JS 命中只是分类线索，继续读入口和依赖以区分浏览器前端、Node 服务、SDK、构建工具和测试。特征计数全部为 0 的目录，列出实际内容复核，不能据 Java 计数为 0 判空仓。未知框架登记 unknown，不自动排除。

XSS/前端相关审查开始前，对照实际目录再次核查前端与模板的存在性、搜索范围和文件类型；本轮可复用未变的枚举证据，但不得沿用未经复核的旧画像。框架 sink 关键词不能代替文件覆盖检查。

按 repo-boundary-manifest.md 登记资产，按 coverage-metrics.md 记录各类必需资产及实际覆盖；缺前端源码或前端未审均不能作整个系统无 XSS 的依据。画像不完整时保守扫描常见输入源并记录具体覆盖缺口。

## 输入源记录

对每个输入源记录：

```
源类型:
位置:
参数或字段:
数据类型:
是否需要认证:
初始可控性:
初始利用前置条件:
```
