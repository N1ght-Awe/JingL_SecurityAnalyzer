路径穿越 ---
name: 路径穿越漏洞分析
description: CWE-22 路径穿越漏洞分析，文件路径用户可控的安全问题
cwe: CWE-22
cvss_base: 7.5
---

## 1. 漏洞概述

路径穿越是攻击者通过在文件路径中注入`../`等跳转符号，访问预期之外的文件或目录。**高危（CVSS 7.5）**，可导致任意文件读取/写入/删除，进而数据泄露、配置篡改、系统破坏或权限提升。

## 2. 危险点清单

### 模式1：直接拼接用户输入（高危）
`../`可穿越到上级目录。
```java
File file = new File(baseDir + "/" + request.getParameter("file"));
```

### 模式2：路径完全用户可控（高危）
可指定任意绝对路径。
```java
new FileInputStream(request.getParameter("path"));
```

### 模式3：new File(baseDir, fileName)拼接（高危）
构造器不会规范化路径，`../`仍有效。
```java
new File(uploadDir, request.getParameter("name"));
```

### 模式4：ZipSlip — ZIP解压路径穿越（高危）
`entry.getName()`可包含`../../`，解压时文件写入预期目录之外。
```java
new File(outputDir, zipEntry.getName());
```

### 模式5：URL路径穿越（高危）
URL路径中的`../`可穿越到上级路径。
```java
new URL(baseUrl + request.getParameter("url"));
```

### 模式6：临时文件路径穿越（中危）
`userFileName`中的`../`与前缀拼接后仍可穿越。
```java
new File(tempDir, System.currentTimeMillis() + "_" + userFileName);
```

### 模式7：文件下载/上传路径穿越（高危）
文件名/路径用户可控，可穿越到任意目录读/写文件。
```java
new FileInputStream(downloadDir + "/" + request.getParameter("file"));
```

## 3. 分析步骤

### 第一步：识别用户输入，跟踪数据流
- HTTP请求参数：`request.getParameter()`、`@RequestParam`、`@PathVariable`
- 文件上传文件名：`MultipartFile.getOriginalFilename()`
- 消息队列、Cookie/Session、JSON/XML请求体
- **如果代码中没有明确的用户输入入口，则认为用户无法输入，不要捏造事实。**

### 第二步：识别文件操作函数
- **读：** `FileInputStream`、`FileReader`、`Files.readAllBytes`
- **写：** `FileOutputStream`、`FileWriter`、`Files.write`、`file.transferTo`
- **删除：** `File.delete`、`Files.delete`
- **创建：** `File.createNewFile`、`Files.createFile`
- **修改：** `File.renameTo`、`Files.move`
- **判断存在：** `File.exists`（需检查后续是否有实际操作）
- **Zip解压：** `ZipInputStream.getNextEntry()`、`ZipEntry.getName()`

### 第三步：危害性验证
- **读取：** 泄露敏感文件；**写入：** 篡改配置/植入恶意代码；**删除：** 破坏关键文件；**Zip解压：** 可写入和覆盖（ZipSlip）
- Windows同时支持`/`和`\`，两者都需考虑

### 第四步：防护机制核验
- **强防护：** `getCanonicalPath+startsWith`、`Path.resolve+normalize+startsWith`、文件名白名单`[a-zA-Z0-9._-]+`、Zip解压路径边界校验
- **弱防护：** 仅`replace("../","")`、仅正则允许`/`、仅`file.exists()`、仅扩展名检查

### 第五步：业务影响评估
- 判断可访问文件类型、操作类型、是否可导致系统失陷

## 4. 证据闭合验证

```
源(Source): 外部输入来源（HTTP参数、上传文件名、Zip条目名等）
传播(Propagation): 从输入源到文件操作API的参数传递路径
Sink: File/Path/InputStream/OutputStream/ZipInputStream等文件操作
防护(Sanitizer): 强防护/弱防护/无防护
守卫(Guard): 认证、角色、接口访问控制
利用前置条件(Preconditions): 攻击者必须能控制文件名/路径或Zip条目名
影响(Impact): 文件泄露/篡改/删除/系统失陷
```

**ZipSlip特殊证据：** Source=攻击者可上传恶意ZIP；Sink=`new File(outputDir, entry.getName())`未校验；Sanitizer=是否在解压前校验路径边界

## 5. 防护措施清单

### 强防护

| 防护措施 | 代码示例 |
|---------|---------|
| getCanonicalPath + startsWith | `canonicalPath.startsWith(canonicalBaseDir + File.separator)` |
| Path.resolve + normalize | `basePath.resolve(fileName).normalize().startsWith(basePath)` |
| 文件名白名单 | `fileName.matches("[a-zA-Z0-9._-]+")` |
| Zip解压安全检查 | `outputDirPath.resolve(entry.getName()).normalize().startsWith(outputDirPath)` |
| UUID重命名 | 替换原始文件名，消除穿越可能 |

### 弱防护

| 防护措施 | 绕过方式 |
|---------|---------|
| 仅过滤`../` | `....//`变种、`..\\`（Windows）、URL编码 |
| 仅正则过滤（允许`/`） | 路径穿越仍可能 |
| 仅检查文件是否存在 | 穿越后文件仍存在 |
| 仅扩展名检查 | 不阻止路径穿越 |

## 6. 常见误报模式

1. **文件路径来自配置文件或常量，非用户可控**：来源于application.properties、final常量或系统环境变量
2. **文件名经过白名单校验**：严格正则`[a-zA-Z0-9._-]+`禁止了穿越符号和路径分隔符
3. **使用Path.resolve().normalize()后进行startsWith校验**：这是强防护
4. **文件名经过UUID重命名**：用户提供的文件名不会用于文件系统路径构造
5. **ZipEntry.getName()经过安全检查后使用**：规范化+前缀校验已做

## 7. 判定标准

### 确认风险（必须同时满足1、2、3、4）
1. ✅ 存在用户输入点（文件名/路径/Zip条目名）
2. ✅ 存在实际文件操作（读/写/删除/创建/Zip解压）
3. ✅ 文件路径/文件名来自用户输入可控
4. ✅ 无有效防护（仅弱防护或无防护）

### 确认误报（满足任意2条）
1. ✅ 存在任一强防护机制
2. ✅ 非实际文件操作（仅exists，后续无操作）
3. ✅ 文件路径和文件名来自系统配置，用户不可控
4. ✅ 文件路径来自数据库且经过白名单验证存储
5. ✅ 仅为测试代码或内部工具

### 缺失关键源码条件
- 无法确定文件路径来源是否用户可控
- 缺少防护措施的完整代码
- 无法确认是否有实际文件操作

## 8. 置信度评估

- **高（95%+）：** 用户直接控制文件路径且无规范化验证，证据链完整
- **中（70-95%）：** 用户可能控制路径但不确定，存在部分防护，数据流不完整
- **低（<70%）：** 无法确定路径是否用户可控，缺少关键防护代码

## 9. 核心纪律

1. **必须检查Zip解压路径：** ZipSlip是特殊高危模式，容易被忽略
2. **必须区分强防护与弱防护：** getCanonicalPath+startsWith是强防护，仅过滤`../`是弱防护
3. **必须区分Windows和Linux：** Windows同时支持`/`和`\`
4. **必须识别实际文件操作：** 仅exists不算，需检查后续读/写/删除
5. **必须追踪数据流：** 从用户输入到文件操作的完整路径
6. **不脑补未看到的事实：** 无法确认时标注"缺失关键源码"

> 【最高优先级】必须完成证据闭合验证：对每条finding证明Source→Propagation→Sink→Sanitizer→Guard→Preconditions→Impact证据链完整，调用链深度不是目标，证据闭合才是。参考 shared-references/proof-patterns.md 中对应漏洞类型的证明模板。