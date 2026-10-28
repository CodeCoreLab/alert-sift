# 变更日志 — 告警降噪网关（alert-sift）

本文件记录本项目的变更。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [未发布]

## [Unreleased]
### Changed
- 产品页 hero 区：「快速开始」跳转改为「下载源码包」下载按钮——fetch 流式读取并显示
  进度百分比（未知总长走不定态），文件名取 `Content-Disposition`（缺失回退 URL 末段，
  保留原扩展名），失败给出可读原因 + 重试 + 直接下载兜底；无流式能力的浏览器降级为
  原生 `<a download>`

## [0.1.0] - 2026-10-27

### 新增

- 首个开源版本：七阶段告警降噪流水线
  （去重 / 静默 / 抑制 / 聚合 / 分级 / 通知 / 持久化）
- AI 运维护栏：MCP Server（16 工具）+ guard
  （RBAC / 高危审批 / 审计 / dry_run）
- Alertmanager webhook v2 兼容入口；vmalert reconcile
- per-robot 令牌桶限流 + 推送健康观测 + 失败落盘审计
- 48 项用例全绿，CI 三版本矩阵

### 变更

- 业务词配置化：`groups.project_names` / `prefixes` / `ip_prefixes`
  （原生产硬编码移除）
- 全局改名 `alert-core` → `alert-sift`（含 metrics 前缀与环境变量前缀）
