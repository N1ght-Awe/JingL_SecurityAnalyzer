# 仓库与边界清单

扫描指定根目录，识别真正的仓库与构建模块，记录排除项；不把所有子目录当独立仓库。

资产在报告 assets 数组登记 asset_id、repo_id、path、kind（frontend/backend/templates/gateway/config/library/other/unknown）、evidence_refs。复合模块可拆为有明确路径的资产；JS/TS 不自动等于 frontend。未提供但已知相关的前端也登记其预期路径并在 coverage 中记未覆盖，不伪造源码引用。

每仓记录 repo_id、path、revision、service_names、inbound、outbound、shared_stores、shared_credentials_refs、evidence_refs、unknown_boundaries。凭据只保留脱敏引用，不保存完整值。

入/出站记录协议、方法与接口/Topic、目标、字段映射和认证上下文。由源码、运行配置或部署清单建立对应关系；外部仓未提供时 target_repo=unknown。画像事实保留生效条件和版本，不视为所有入口的统一安全证明。
