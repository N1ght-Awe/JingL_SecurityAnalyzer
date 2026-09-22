# 覆盖与成本

在画像时建立统计，扫描期间累计，结束时核对。所有不可得数值写 null 和原因，不能填 0 代替未知。

## 必需资产与覆盖结论

2.1.0 报告使用 scan_types、assets、coverage、coverage_status。每个选中类型有一条 coverage：type、required_asset_ids、reviewed_asset_ids、status（complete/partial）、gaps、evidence_refs。required 根据实际威胁面与资产枚举确定，不按搜索命中反推；reviewed 表示完成声明规则范围的审查，不只是列目录或搜到关键词。源码缺失、搜索失败、截断未处理、框架不支持均保留在 gaps 和未审资产中。

XSS 必需范围包括已登记 frontend/templates，及相关 backend/API 输出；完整系统范围未提供前端时登记预期资产并记缺口。SQL 关注真实查询构造/Mapper/Provider，权限关注网关/后端/实际策略，其他类型按入口和证明目标确定。范围确实只有后端时可作限定后端结论，但不能声称整个系统无 XSS。

complete 要求 required 全部 reviewed 且 gaps 为空；其他为 partial，报告 coverage_status 为 partial。即使集合相等，只要语言/框架/搜索仍有缺口也只能 partial。coverage 中必须覆盖 scan_types 所有类型；允许部分报告与局部 finding。完整仅表示声明范围完成，不保证无漏洞。校验器核对集合与已登记前端义务，不能发现未被如实登记的仓库或判断实际代码是否读完。

范围：仓库/提交、模块、生产/测试/生成文件数、支持语言、排除路径及原因、入口类别和已检查入口、实际已读文件、已审代码范围、截断与未重试搜索。扫描完成仅指声明范围和规则计划完成，不保证不存在漏洞。

漏斗：raw_hits（去重前命中）、candidates（本轮账本中去重后的调用实例数）、reviewed、pending_review、source_closed、validation_selected、validation_executed、validation_passed、unresolved。2.3起同一instance_key重复命中沿用ID；不同入口、调用点或独立操作分别登记、审结和计数，即使根因相同。根因只用于分组与修复关联，不代替候选数，也不通过合并删除实例；误报、延期与未解决项仍在账本和findings中。

`candidates = len(findings) = reviewed + pending_review`，并与本轮候选账本实例数对账；报告status计数之和等于候选数。pending_review仅计status=待审查；reviewed计其余状态，包含已初审但缺源码或待验证的实例，不表示全部终审闭合或运行验证通过。验证计数按明确覆盖的finding实例分别核对，执行命令次数另计；一条suite回执可列多个实例，但不能把未列出或未实际验证的兄弟实例计为PASSED。控制侧观察、防护条目与根因分组数分别列示，不混加。历史报告保留当时口径，比较前显式核对，不自动改写历史计数。

成本：phase_wall_seconds、total_wall_seconds、input_tokens、output_tokens、cached_tokens、model、provider_usage_basis、loaded_reference_chars、build_count、build_reused、retry_count、blocked_reasons。并行墙钟时间不等于各任务用时之和；字符数不是 token 数。

对比运行必须固定仓库提交、范围、模型配置、运行环境与规则版本。质量用人工复核的真阳性/误报、漏检检查和未解决比例；没有真值不能报准确率/召回率。

历史扫描速度/消耗如仅用户描述，以“用户报告，未复测”记录；本仓维护校验不是业务扫描性能测试。后续真实环境比较版本时同时交付证据和遗漏清单，不只比较耗时。
