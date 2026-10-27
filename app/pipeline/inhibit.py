# -*- coding: utf-8 -*-
"""L4 抑制 —— 父告警压制子告警（config/inhibits.yaml）

典型场景：主机宕机(instance down) 时，压制该主机上的 CPU/磁盘/进程等子告警，
避免告警风暴。

⚠️ 命名注意（P3-⑧，2026-08-25 澄清）：本实现的 source/target 语义与
Alertmanager inhibit_rules 的命名**相反**，属设计取舍（配置与代码自洽）：
  * source_matchers = 匹配【当前告警】→ 它成为被抑制方（子告警）
  * target_matchers = 匹配【活跃父告警】→ 它成为抑制方（父告警）
    （Alertmanager 中 source=父、target=子）
因此编写 inhibits.yaml 时务必按 inhibits.yaml 顶部注释的语义填写，
不要照搬 Alertmanager 文档的 source/target 理解。

重构（2026-08-15）：
  * 提取 _MATCH_KEYS 常量，消除重复的 ctx 构造逻辑（DRY）
  * 增加 early return，减少嵌套层级
  * 增加边界校验：空 matchers 不抑制
"""
from __future__ import annotations

import logging
from typing import Any

from models import Alert

logger = logging.getLogger("alert-sift.inhibit")

# 匹配上下文时使用的键集合
_MATCH_KEYS = ("rule_name", "alertname")


def is_inhibited(alert: Alert, state: dict[str, Any]) -> bool:
    """判断告警是否被父告警抑制。

    Args:
        alert: 待检查的告警对象。
        state: 包含 cfg 和 store 的状态字典。

    Returns:
        True=被抑制（跳过推送），False=正常处理。
    """
    # 恢复事件不抑制
    if alert.status == "resolved":
        return False

    inhibit_rules = state.get("cfg", {}).get("inhibits", [])
    if not inhibit_rules:
        return False

    for rule in inhibit_rules:
        if not rule.get("source_matchers"):
            continue

        # 1) 当前告警是否属于"被抑制方"
        if not _match_ctx(alert, rule.get("source_matchers", {})):
            continue

        # 2) 是否存在命中"抑制方"的活跃父告警
        parent = _find_parent(alert, state, rule)
        if parent:
            logger.info(
                "告警 %s 被父告警 %s 抑制", alert.fingerprint, parent.fingerprint
            )
            # 命中打点（P0-③，失败不影响链路）
            try:
                import metrics as _m
                _m.inc("alert_sift_inhibited_total")
            except Exception as _exc:  # noqa: BLE001
                logger.debug("忽略预期内异常（降级路径）: %s", _exc)
            return True

    return False


def _match_ctx(alert: Alert, matchers: dict) -> bool:
    """匹配上下文 = labels + rule_name（与 silence 一致，兼容 rule_name 匹配）。"""
    if not matchers:
        return False

    ctx = dict(alert.labels)
    ctx["rule_name"] = alert.rule_name
    ctx["alertname"] = alert.rule_name
    return _match_any(ctx, matchers)


def _match_any(labels: dict, matchers: dict) -> bool:
    """精确匹配：所有 matcher 键值对都相等才返回 True。"""
    for k, v in matchers.items():
        if labels.get(k) != v:
            return False
    return True


def _find_parent(alert: Alert, state: dict[str, Any], rule: dict) -> Alert | None:
    """在活跃告警中寻找命中 target_matchers 且关联键相同的父告警。"""
    target = rule.get("target_matchers", {})
    equal = rule.get("equal", [])

    active_alerts = state.get("store").get_active_alerts()
    for active_data in active_alerts:
        # 兼容 dict 与对象两种存储形态
        if isinstance(active_data, dict):
            active = Alert(
                rule_name=active_data.get("rule_name", ""),
                labels=active_data.get("labels", {}),
                annotations=active_data.get("annotations", {}),
                status=active_data.get("status", "firing"),
                severity=active_data.get("severity", "P3"),
                project=active_data.get("project", "SYS"),
                fingerprint=active_data.get("fingerprint", ""),
            )
        else:
            active = active_data

        # 自匹配检查
        if active.fingerprint == alert.fingerprint:
            continue

        # 父告警必须为 firing 状态
        if active.status != "firing":
            continue

        # 命中抑制方
        if not _match_ctx(active, target):
            continue

        # equal 字段：关联键须相同
        if all(active.labels.get(k) == alert.labels.get(k) for k in equal):
            return active

