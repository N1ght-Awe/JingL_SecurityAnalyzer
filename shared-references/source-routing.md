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

如果画像不完整，保守扫描常见输入源，并在扫描统计中标注"项目画像不完整"。

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