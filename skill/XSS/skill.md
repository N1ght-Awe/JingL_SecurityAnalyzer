---
name: XSS漏洞分析
description: CWE-79 跨站脚本漏洞分析；用于审查前端或服务端中不可信数据进入 HTML、属性、URL、JavaScript 或 CSS 渲染上下文的情况。
---

## 1. 漏洞概述

攻击者可控内容在实际浏览器上下文被解释为可执行内容，且适用防护未阻断时才支持 XSS。存储/反射描述输入持久化方式，DOM 描述浏览器侧处理，两者可以重叠；不能因是存储型就只审后端。

## 2. 危险点清单

- HTML sink：innerHTML/outerHTML/insertAdjacentHTML/document.write/createContextualFragment、jQuery html/append/prepend。
- Vue v-html、React dangerouslySetInnerHTML、Angular innerHTML/信任值绕过；正常绑定与净化能力按实际框架核验。
- eval/Function、字符串 setTimeout/setInterval、script.src；location/href/window.open 等需实际协议/浏览器语义，非任意 URL 可控都是 XSS。
- 事件属性、srcdoc、style/srcset 等上下文，逐项证明可执行解释而非仅属性可控。
- 模板不转义输出、服务端 HTML/内联 JS 拼接、富文本写→存→读→渲染与二次读取。
- 过滤/AOP 未激活或通道缺口、输出编码上下文不匹配、后续重解析与服务配置差异。

## 3. 分析步骤

1. 按 source-routing/coverage-metrics 复核真实前端、模板和相关 API 范围；缺源码与存在未审分别记录。
2. 从具体 sink 逆向追踪 location.search/hash、referrer、postMessage、window.name、API/数据库等来源，再正向核验攻击者控制、传播变换和受害者触发条件。
3. 区分 HTML 文本/属性/URL/JS/CSS 上下文。th:inline=javascript 是上下文线索，继续检查实际转义内联和不转义表达式，不能仅按属性名确认。
4. 阅读当前字段净化/编码实现、框架绑定与配置，检查之后解码、拼接、DOM 重解析/间接 sink；同一函数的已审合同可以复用。
5. 存储链闭合写入主体、保存、读取和实际展示端；前端受害者路径与业务权限也是前提。
6. 控制侧检查实际过滤器/AOP 注册与生效、相关通道覆盖及输出侧控制；参数包装器不覆盖 JSON 不代表整个 API 无防护。编码后的安全反射不自动形成建议。控制侧通用步骤见 shared-references/protection-audit-methodology.md；已审实现按 shared-references/control-knowledge.md 复用，逐路径核验调用、适用性与后续影响。

## 4. 证据闭合验证

Source 为不可信内容，Propagation 为前后端传播/持久化，Sink 为实际可执行上下文，Sanitizer 为同字段/上下文适用防护，Guard 为访问控制，Transport 为相关跨边界传输，Preconditions 为受害者触发/权限/浏览器条件，Impact 为可支持的会话或操作影响。

## 5. 防护措施清单

当前上下文有效编码/成熟净化器及适用配置、正常文本绑定、受约束可信类型策略并覆盖后续处理。库名称、未调用 bypassSecurityTrust、CSP/HttpOnly 或另一字段已编码都不单独排除。replaceAll 的效果由转换与上下文决定，替换 < 为实体不是“删除式”同义词。

## 6. 常见误报模式

内容固定且来源不可影响；同字段的有效上下文防护持续到最终解释；实际为文本节点/正常插值且无后续 HTML 重解析。前端缺失不作误报或无 XSS 证明，而是覆盖缺口。

## 7. 判定标准

最终 status 与执行状态遵循 shared-references/proof-schema.md；下述为源码判据。源码确认须闭合攻击者可控内容、实际可执行上下文、触发前提、适用防护与相称影响；运行确认按真实测试浏览器/目标验证。只输出 HTML 或命中 innerHTML 不足。未读代码保持待审查，未提供实现才记缺失关键源码。

## 8. 置信度评估

按控制、解释上下文、前提、防护和影响证据描述；只有 Source→API 链不自动高置信。未覆盖前端单列，不用低置信掩盖漏扫。

## 9. 核心纪律

不因存在浏览器 sink 就确认，不因已有写入过滤就跳过展示端。真实局部渲染可支持局部结论；未执行的页面/身份链不能宣称端到端复现。
