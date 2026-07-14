SQL注入---
name: SQL注入漏洞分析
description: MyBatis/MyBatis-Plus SQL注入漏洞分析，包括XML配置和Wrapper动态SQL
cwe: CWE-89
cvss_base: 9.8
---

## 1. 漏洞概述

SQL注入是攻击者在数据库查询中注入恶意SQL代码。在MyBatis/MyBatis-Plus中，不当使用`${}`参数或Wrapper动态方法可导致注入。**严重（CVSS 9.8）**，可导致全量数据泄露、数据篡改/删除、权限提升或系统失陷。

## 2. 危险点清单

### 2.1 MyBatis XML — `${}`直接拼接（高危）
`${}`是文本替换占位符，用户输入直接拼接到SQL，无参数化保护。
```xml
SELECT * FROM users WHERE name = '${name}'
```

### 2.2 MyBatis XML — 动态SQL标签/`<script>`内`${}`（高危）
`<if>`、`<choose>`、`<bind>`、`<script>`标签内使用`${}`同样危险。
```xml
<if test="name != null">AND name LIKE '%${name}%'</if>
<script>SELECT * FROM users WHERE name = '${name}'</script>
```

### 2.4 MyBatis XML — ORDER BY注入（高危）
ORDER BY位置无法使用`#{}`，`${}`直接拼接排序字段/方向，构成标识符注入。
```xml
SELECT * FROM users ORDER BY ${orderByField}
```

### 2.5 MyBatis XML — 标识符注入（高危）
表名、列名、别名等SQL标识符位置无法使用`#{}`，必须使用强白名单映射。
```xml
SELECT * FROM ${tableName}
SELECT ${columnName} FROM users
```

### 2.6 MyBatis-Plus Wrapper动态方法（高危）
- **`.last(userInput)`**：拼接SQL片段到查询末尾
- **`.apply(userInput)`**：拼接SQL条件片段
- **`.inSql("id", userInput)`**：接受用户可控子查询
- **`.exists(userInput)`/`.notExists(userInput)`**：接受用户可控子查询
- **`.orderBy(true, true, userColumns)`**：用户可控列名拼接到ORDER BY

### 2.10 MyBatis-Plus — `${ew.customSqlSegment}`（高危）
Wrapper动态SQL片段通过customSqlSegment进入XML拼接。
```xml
SELECT * FROM users ${ew.customSqlSegment}
```

## 3. 分析步骤

### 第一步：识别SQL注入点
- **MyBatis XML：** 扫描所有`${}`位置，区分WHERE值位置 vs ORDER BY位置 vs 标识符位置
- **MyBatis-Plus Wrapper：** 识别`.last()`、`.apply()`、`.inSql()`、`.exists()`、`.notExists()`方法及`${ew.customSqlSegment}`

### 第二步：输入溯源
- 确认`${}`或Wrapper方法参数来源
- `#{}`安全（预编译参数绑定），`${}`危险（文本替换）
- 硬编码常量/枚举 → 不可控；请求参数 → 可控

### 第三步：危害性验证
- **WHERE值位置`${}`：** 可注入UNION SELECT、OR条件，数据泄露风险高
- **ORDER BY/标识符位置`${}`：** 标识符注入，无法使用`#{}`，需强白名单
- **Wrapper动态方法：** `.last()`可注入任意SQL片段

### 第四步：防护机制核验
- **强白名单：** 后端枚举映射（`Enum.valueOf`）、Map映射（`sortMapping.get(sort)`）、Switch常量映射
- **弱防护：** 黑名单关键词过滤、正则过滤（未绑定业务白名单）、长度限制、字符替换

### 第五步：业务影响评估
- 判断注入类型、可访问数据范围、修复紧急程度

## 4. 证据闭合验证

```
源(Source): 外部输入来源（HTTP参数、JSON Body、消息队列等）
传播(Propagation): 从输入源到Mapper/Wrapper的参数传递路径
Sink: ${}拼接位置或Wrapper动态方法调用
防护(Sanitizer): 强白名单/弱防护/无防护
守卫(Guard): 认证、角色、接口访问控制
利用前置条件(Preconditions): 攻击者必须能访问该端点并影响参数
影响(Impact): 数据泄露/篡改/命令执行范围
```

**关键：** 调用链深度不是目标，证据闭合才是。

## 5. 防护措施清单

### 强防护

| 防护措施 | 代码示例 |
|---------|---------|
| `#{}`参数化查询 | `<where>name = #{name}</where>` |
| 后端枚举映射 | `SortField.valueOf(sort)` |
| 后端Map映射 | `sortMapping.get(sort)` |
| Switch常量映射 | `switch(sort) { case "name": col = "user_name"; }` |
| LambdaQueryWrapper | `wrapper.eq(User::getName, name)` |

### 弱防护

| 防护措施 | 绕过方式 |
|---------|---------|
| 黑名单关键词过滤 | 其他注入方式、编码绕过 |
| 正则过滤（未绑定业务白名单） | 可能遗漏注入向量 |
| 长度限制 | 不阻止短注入片段 |
| 字符替换 | 双写绕过、其他字符 |

## 6. 常见误报模式

1. **MyBatis使用`#{}`参数化查询**：`#{}`底层使用PreparedStatement参数绑定，安全
2. **`${}`用于ORDER BY但排序字段来自后端枚举或Map白名单**：用户输入只能映射为预定义固定值
3. **Wrapper.last()/apply()的参数来自内部计算而非用户输入**：来源于常量/配置文件
4. **动态SQL标签的判断条件基于常量或配置**：SQL动态构造完全由代码逻辑控制
5. **LambdaQueryWrapper使用方法引用**：编译期确定列名，无字符串暴露风险

## 7. 判定标准

### 确认风险（必须同时满足1、2，且满足3-5中至少1条）
1. ✅ 使用`${}`拼接或Wrapper动态方法，且参数用户可控
2. ✅ 无强白名单防护
3. ✅ 用于WHERE条件、ORDER BY、标识符等关键位置
4. ✅ 仅采用黑名单过滤或正则过滤（弱防护）
5. ✅ 生产环境下存在可被利用的SQL注入点

### 确认误报（满足任意2条）
1. ✅ 完全使用`#{}`预编译参数
2. ✅ `${}`参数使用前进行了枚举/Map白名单验证
3. ✅ LambdaQueryWrapper使用方法引用
4. ✅ ORDER BY经过后端枚举/Map白名单映射
5. ✅ 测试环境或Mock数据

### 缺失关键源码条件
- 无法确认`${}`参数来源是否用户可控
- 缺少白名单验证的完整代码
- 无法确认Wrapper方法的参数来源

## 8. 置信度评估

- **高（95%+）：** 明确`${}`拼接用户输入，无任何白名单验证，证据链完整
- **中（70-95%）：** 存在`${}`使用但参数来源不确定，存在部分验证
- **低（<70%）：** 无法确认参数是否用户可控，缺少关键验证代码

## 9. 核心纪律

1. **必须区分`#{}`和`${}`**：`#{}`安全（参数化），`${}`危险（文本替换）
2. **必须区分ORDER BY/标识符注入与WHERE注入**：ORDER BY和标识符位置无法使用`#{}`，判定标准不同
3. **必须区分强白名单与弱防护**：枚举/Map映射是强白名单，正则/黑名单是弱防护
4. **必须追踪数据流**：从用户输入到SQL构建的完整路径
5. **必须验证防护措施有效性**：读取防护代码实现，不可凭函数名推断
6. **不脑补未看到的事实**：无法确认时标注"缺失关键源码"

> 【最高优先级】必须完成证据闭合验证：对每条finding证明Source→Propagation→Sink→Sanitizer→Guard→Preconditions→Impact证据链完整，调用链深度不是目标，证据闭合才是。参考 shared-references/proof-patterns.md 中对应漏洞类型的证明模板。