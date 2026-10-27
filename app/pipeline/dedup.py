# -*- coding: utf-8 -*-
"""L2 指纹去重 —— 窗口内同一 fingerprint 只保留一次状态变更（轻量版 2026-09-04）

策略（生产验证生效：firing_short 431 / repeat_long 69 / resolved_debounce 32 / storm 1324 次拦截）：
  1. resolved 去抖：短窗口内同指纹已通知过恢复 → 跳过（防阈值边缘横跳刷屏）
  2. firing 短窗口：同指纹已通知 → 跳过（抖动抑制）
  3. 风暴折叠：同 rule_name 1h 推送超上限 → 折叠（P0 豁免）
  4. firing 长窗口：P0 豁免；P1/P2 按 severity 分级重提醒窗口

P0 判定：显式 severity=P0 或 type=biz（本模块运行于 classify 之前，severity 可能为空）。
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any

from models import Alert

logger = logging.getLogger("alert-sift.dedup")

# 短窗口默认 600s（config window_seconds），长窗口默认 7200s
_DEFAULT_DEDUP_WINDOW = 600
_DEFAULT_REPEAT_WINDOW = 7200
# per-severity 长窗口兜底（config severity_repeat_seconds 未配置时使用）
_SEVERITY_REPEAT_FALLBACK = {"P1": 3600, "P2": 28800}
# 单规则风暴上限：同 rule_name 1h 窗口推送超过该值 → 折叠跳过
_DEFAULT_STORM_LIMIT = 30
_STORM_WINDOW = 3600  # 风暴窗口 1h


# P0-3 修复（2026-10-05）：统一引用 severity.is_p0（消除 4 处判定不一致）
from severity import is_p0 as _is_p0


def _to_int(value, ctx=""):
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"非法整数{(' ' + ctx) if ctx else ''}: {value!r}") from exc


def _parse_ts(value: Any) -> float | None:
    """meta 时间戳解析：脏数据/None 安全，返回 None 视为无记录。"""
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _repeat_window(dedup_cfg: dict, severity: str | None, base_repeat: int) -> int:
    """按 severity 解析长节流窗口（P1/P2 分级，未配置回退 base_repeat）。"""
    sev_repeat = dedup_cfg.get("severity_repeat_seconds", {})
    return _to_int(sev_repeat.get(
        severity or "P2",
        _SEVERITY_REPEAT_FALLBACK.get(severity or "P2", base_repeat)))


def _storm_folded(alert: Alert, state: dict[str, Any], now: float) -> bool:
    """单规则风暴折叠检测。

    meta 键 `storm:{rule_name}` 存 JSON {"cnt": n, "win": first_ts}：
    1h 窗口内推送计数 > 上限（config dedup.storm_limit，默认 30）→ 折叠跳过。
    P0 豁免；折叠时计数继续累加（供审计）。
    """
    if _is_p0(alert):
        return False

    dedup_cfg = state.get("cfg", {}).get("dedup", {})
    limit = _to_int(dedup_cfg.get("storm_limit", _DEFAULT_STORM_LIMIT))

    key = f"storm:{alert.rule_name}"
    raw = state.get("store").get_meta(key)
    cnt, win = 0, now
    if raw:
        try:
            data = json.loads(raw)
            cnt, win = int(data.get("cnt", 0)), float(data.get("win", now))
        except (ValueError, TypeError):
            cnt, win = 0, now

    # 窗口滚动：超过 1h 重置计数
    if now - win > _STORM_WINDOW:
        cnt, win = 0, now

    cnt += 1
    state.get("store").set_meta(
        key, json.dumps({"cnt": cnt, "win": win}), ttl=_STORM_WINDOW * 2)

    if cnt > limit:
        try:
            import metrics as _m
            _m.inc("alert_sift_storm_folded_total", rule_name=alert.rule_name)
        except Exception as _exc:  # noqa: BLE001 —— 打点失败不阻断
            logger.debug("忽略预期内异常（降级路径）: %s", _exc)
        if cnt == limit + 1:
            logger.warning(
                "单规则风暴折叠 rule=%s 第 %d 次触发（上限 %d/1h），后续推送已折叠仅计数",
                alert.rule_name, cnt, limit)
        return True
    return False


def should_skip(alert: Alert, state: dict[str, Any]) -> bool:
    """判断告警是否应被去重跳过。

    Args:
        alert: 待处理的告警对象。
        state: 包含 cfg 和 store 的状态字典。

    Returns:
        True=跳过推送，False=正常处理。
    """
    dedup_cfg = state.get("cfg", {}).get("dedup", {})
    window = dedup_cfg.get("window_seconds", _DEFAULT_DEDUP_WINDOW)
    base_repeat = dedup_cfg.get("repeat_interval_seconds", _DEFAULT_REPEAT_WINDOW)

    now = time.time()
    store = state.get("store")

    # resolved 事件去抖：短窗口内已通知过恢复 → 跳过（防抖动刷屏）
    if alert.status == "resolved":
        last_resolved = _parse_ts(store.get_meta(f"resolved:{alert.stable_fingerprint}"))
        if last_resolved is not None and (now - last_resolved) < window:
            _skip_metric("resolved_debounce")
            return True
        store.set_meta(f"resolved:{alert.stable_fingerprint}", str(now), ttl=window)
        return False

    # firing：短窗口抖动抑制
    key = f"dedup:{alert.stable_fingerprint}"
    repeat_key = f"repeat:{alert.stable_fingerprint}"

    last_ts = _parse_ts(store.get_meta(key))
    if last_ts is not None and (now - last_ts) < window:
        _skip_metric("firing_short")
        return True

    # 单规则风暴折叠：同 rule_name 1h 窗口推送超上限 → 折叠
    # （须在长窗口之前：持续 firing 的同指纹被 repeat_long 拦截后风暴计数不增长）
    if _storm_folded(alert, state, now):
        return True

    # 长窗口节流：P0 豁免；P1/P2 按 severity 分级窗口
    repeat_window = base_repeat
    if not _is_p0(alert):
        repeat_window = _repeat_window(dedup_cfg, alert.severity, base_repeat)
        last_notified = _parse_ts(store.get_meta(repeat_key))
        if last_notified is not None and (now - last_notified) < repeat_window:
            _skip_metric("repeat_long")
            return True

    # 首次通知 / 超出节流周期：刷新窗口
    store.set_meta(key, str(now), ttl=window)
    # TTL 必须覆盖最长节流窗口（原 ttl=base_repeat < P2 28800 → TTL 击穿）
    store.set_meta(repeat_key, str(now), ttl=max(repeat_window, base_repeat))
    return False


def _skip_metric(reason: str) -> None:
    """去重跳过打点（失败不影响链路）。"""
    try:
        import metrics as _m
        _m.inc("alert_sift_dedup_skip_total", reason=reason)
    except Exception as _exc:  # noqa: BLE001
        logger.debug("忽略预期内异常（降级路径）: %s", _exc)
