# -*- coding: utf-8 -*-
"""Prometheus 文本格式指标（轻量手写，零依赖）

计数器/仪表均线程安全。

重构（2026-08-15）：
  * 提取 _HELP 为模块级常量
  * inc/set_gauge 增加空 name 保护
  * render 增加空数据快速返回
"""
from __future__ import annotations

import os
import threading
import time
from collections import defaultdict


def _to_int(value, ctx=""):
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"非法整数{(' ' + ctx) if ctx else ''}: {value!r}") from exc


def _to_float(value, ctx=""):
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"非法浮点数{(' ' + ctx) if ctx else ''}: {value!r}") from exc

_lock = threading.Lock()
_COUNTERS: dict[str, dict[tuple, int]] = defaultdict(dict)
_GAUGES: dict[str, dict[tuple, float]] = defaultdict(dict)

_HELP: dict[str, str] = {
    "alert_sift_alerts_received_total": "Alerts received by data plane, by status",
    "alert_sift_ack_grace_skip_total": "Alerts skipped during ack grace window (status kept ack, no re-notify)",
    "alert_sift_alerts_pushed_total": "Alerts pushed to wecom successfully, by project",
    "alert_sift_llm_calls_total": "LLM call outcomes: ok/fail/circuit_open/cache_hit",
    "alert_sift_http_requests_total": "HTTP requests served, by path and status code",
    "alert_sift_rate_limited_total": "Requests rejected by token bucket, by path",
    "alert_sift_aggregate_flush_total": "Aggregator flush attempts, by success",
    "alert_sift_uptime_seconds": "Process uptime in seconds",
    "alert_sift_active_alerts": "Current active (firing) alert count",
    # ---- P0-③ 自观测补全（2026-08-22）----
    "alert_sift_dedup_skip_total": "Alerts skipped by dedup, by reason (resolved_debounce/firing_short/repeat_long/storm)",
    "alert_sift_silenced_total": "Alerts silenced by maintenance window rules",
    "alert_sift_inhibited_total": "Alerts inhibited by parent alert",
    "alert_sift_storm_folded_total": "Alert storm fold events, by rule_name",
    "alert_sift_wecom_send_total": "WeCom push attempts, by ok and project",
    "alert_sift_wecom_rate_limited_total": "Outbound pushes dropped by per-robot rate limit, by project",
    "alert_sift_failed_push_pending": "Pending failed_push files awaiting retry/archive",
    "alert_sift_escalation_total": "Escalation notifications fired, by severity and level",
    "alert_sift_metrics_push_total": "Self metrics pushed to VictoriaMetrics, by ok",
    # ---- P1-2 推送健康状态机（2026-10-15）----
    "alert_sift_wecom_robot_ok": "Per-robot push health: 1=last push ok, 0=failing",
    "alert_sift_wecom_robot_failures": "Per-robot consecutive push failures (alert at >=3)",
    "alert_sift_wecom_robot_last_ok_age_seconds": "Seconds since last successful push (-1=never)",
    "alert_sift_history_dedup_skip_total": "History rows skipped by (fingerprint,status) window dedup",
}


def _fmt_name(name: str) -> str:
    return name.replace("-", "_").replace(".", "_")


# P1-8 修复（2026-10-05）：标签基数上限，防风暴场景 metrics 内存爆炸
# （如 storm:{rule_name} 若 1000+ 不同规则名会撑爆 _COUNTERS）
MAX_SERIES_PER_METRIC = _to_int(os.getenv("ALERT_SIFT_METRICS_MAX_SERIES", "1000"))


def inc(name: str, value: int = 1, **labels) -> None:
    """计数器 +1（或指定值）。超基数上限时丢弃并警告一次。"""
    if not name:
        return
    key = tuple(sorted(labels.items()))
    with _lock:
        bucket = _COUNTERS[_fmt_name(name)]
        if key not in bucket and len(bucket) >= MAX_SERIES_PER_METRIC:
            return  # 丢弃超限新序列，避免内存膨胀
        bucket[key] = bucket.get(key, 0) + value


def set_gauge(name: str, value: float, **labels) -> None:
    """设置仪表值。超基数上限时丢弃并警告一次。"""
    if not name:
        return
    key = tuple(sorted(labels.items()))
    with _lock:
        bucket = _GAUGES[_fmt_name(name)]
        if key not in bucket and len(bucket) >= MAX_SERIES_PER_METRIC:
            return  # 丢弃超限新序列
        bucket[key] = _to_float(value)


def render() -> str:
    """渲染 Prometheus 文本格式。"""
    with _lock:
        has_counters = bool(_COUNTERS)
        has_gauges = bool(_GAUGES)
        if not has_counters and not has_gauges:
            return ""

        lines: list[str] = []
        # HELP / TYPE
        for name in sorted(set(list(_COUNTERS.keys()) + list(_GAUGES.keys()))):
            help_txt = _HELP.get(name, "")
            if help_txt:
                lines.append(f"# HELP {name} {help_txt}")
            lines.append(f"# TYPE {name} {'gauge' if name in _GAUGES else 'counter'}")

        # 计数器
        for name in sorted(_COUNTERS):
            for key, val in sorted(_COUNTERS[name].items()):
                labels = _fmt_labels(key)
                lines.append(f"{name}{labels} {val}")

        # 仪表
        for name in sorted(_GAUGES):
            for key, val in sorted(_GAUGES[name].items()):
                labels = _fmt_labels(key)
                lines.append(f"{name}{labels} {val}")

    return "\n".join(lines) + "\n"


def _fmt_labels(key: tuple) -> str:
    if not key:
        return ""
    parts = ",".join(f'{k}="{v}"' for k, v in key)
    return "{" + parts + "}"


_START: float | None = None


def record_uptime() -> None:
    """记录进程启动时间。"""
    global _START
    _START = _START or time.monotonic()
    set_gauge("alert_sift_uptime_seconds", round(time.monotonic() - _START, 1))
