# -*- coding: utf-8 -*-
"""统一 P0 判定（P0-3 修复，2026-10-05）

原问题：P0 判定散落在 4 处（dedup/aggregate/notify/escalation），语义不一致：
  * dedup: severity=="P0" or type=="biz"  （在 classify 之前，拿不到 severity）
  * aggregate: severity=="P0"
  * notify: severity=="P0"
  * escalation: 按 severity 匹配
导致 dedup 阶段的 type=biz 兜底在其他层失效，P0 告警可能被误拦。

改造：抽出 is_p0(alert) 单一函数，全项目引用同一入口。
P0 判定优先级：显式 severity=P0 → 业务类型 type=biz → 特殊规则名关键词。
"""
from __future__ import annotations


# 业务级标签（等价于 P0）
_BIZ_TYPES = {"biz"}

# 特殊规则名关键词（P0 兜底，规则作者未打 severity 时使用）
# 与 classify 中的规则命名约定 SYS|Type|Severity|Event 对齐
_P0_RULE_KEYWORDS = (
    "LatencyHigh",   # 交易延迟过高
    "ErrorRateHigh", # 接口错误率过高
    "ConnPoolExhausted",  # 数据库连接池耗尽
    "BizDown",      # 业务中断
)


def is_p0(alert) -> bool:
    """判定告警是否为 P0 级别。

    优先级：显式 severity=P0 > type=biz > 规则名关键词。
    alert 可以是 Alert dataclass 或 dict（兼容 store 返回的 payload）。
    """
    # 兼容 Alert 对象与 dict 两种形态
    if isinstance(alert, dict):
        severity = str(alert.get("severity", "") or "").upper()
        labels = alert.get("labels", {}) or {}
        rule_name = alert.get("rule_name", "") or ""
        # 也支持 alertname
        if not rule_name:
            rule_name = labels.get("alertname", "") or ""
    else:
        severity = str(getattr(alert, "severity", "") or "").upper()
        labels = getattr(alert, "labels", {}) or {}
        rule_name = getattr(alert, "rule_name", "") or ""
        if not rule_name:
            rule_name = labels.get("alertname", "") or ""

    # 1) 显式 severity=P0
    if severity == "P0":
        return True

    # 2) 业务类型标签 type=biz
    if str(labels.get("type", "") or "").lower() in _BIZ_TYPES:
        return True

    # 3) 规则名关键词兜底
    for kw in _P0_RULE_KEYWORDS:
        if kw in rule_name:
            return True

    return False
