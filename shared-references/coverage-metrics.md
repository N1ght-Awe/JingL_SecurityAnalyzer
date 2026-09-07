# 覆盖与成本

在画像时建立统计，扫描期间累计，结束时核对。所有不可得数值写 null 和原因，不能填 0 代替未知。

范围：仓库/提交、模块、生产/测试/生成文件数、支持语言、排除路径及原因、入口类别和已检查入口、实际已读文件、已审代码范围、截断与未重试搜索。扫描完成仅指声明范围和规则计划完成，不保证不存在漏洞。

漏斗：raw_hits（去重前命中）、candidates（根因去重后）、reviewed、pending_review、source_closed、validation_selected、validation_executed、validation_passed、unresolved。分别定义，不能混加。`candidates = reviewed + pending_review`；报告 status 计数之和等于候选数；验证计数与 finding 原始记录一致。

成本：phase_wall_seconds、total_wall_seconds、input_tokens、output_tokens、cached_tokens、model、provider_usage_basis、loaded_reference_chars、build_count、build_reused、retry_count、blocked_reasons。并行墙钟时间不等于各任务用时之和；字符数不是 token 数。

对比运行必须固定仓库提交、范围、模型配置、预算与规则版本，并注明冷/热缓存。质量用人工复核的真阳性/误报、漏检检查和未解决比例；没有真值不能报准确率/召回率。

历史扫描速度/消耗如仅用户描述，以“用户报告，未复测”记录；本仓维护校验不是业务扫描性能测试。后续真实环境比较版本时同时交付证据和遗漏清单，不只比较耗时。
