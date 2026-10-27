# -*- coding: utf-8 -*-
"""L3 静默 —— 维护窗口/标签匹配静默（config/silences.yaml）

时间窗三态（优先级从高到低）：
  * schedule  : 周期性维护窗口（如每周一~五 00:00-01:00、每日 22:00-06:00 跨午夜）
  * starts_at / ends_at : 一次性窗口（RFC3339 UTC，缺省=永久）
  * 两者皆空 : 永久静默

周期 schedule 结构：
    schedule:
      timezone: Asia/Shanghai        # 可选，默认 UTC
      weekdays: [mon, tue]           # 可选；0-6 或 mon..sun；空=每天
      start: "00:00"                 # HH:MM 本地时间
      end: "01:00"                   # HH:MM；end <= start 视为跨午夜窗口
"""
from __future__ import annotations

import logging
from datetime import datetime, time, timezone
from typing import Any

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - 仅兼容极老 Python
    ZoneInfo = None

from models import Alert

logger = logging.getLogger("alert-sift.silence")

_WEEKDAY_NAMES = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}


def is_silenced(alert: Alert, state: dict[str, Any]) -> bool:
    """判断告警是否命中静默规则。

    Args:
        alert: 待检查的告警对象。
        state: 包含 cfg 的状态字典。

    Returns:
        True=命中静默（跳过推送），False=正常处理。
    """
    silences = state.get("cfg", {}).get("silences", [])
    if not silences:
        return False

    now = datetime.now(timezone.utc)

    for sil in silences:
        matchers = sil.get("matchers", {})
        if not matchers:
            continue

        if not _match_labels(alert, matchers):
            continue

        # 时间窗判断（schedule 周期优先；其次 RFC3339 一次性；都空=永久）
        if not _within_silence_window(sil, now):
            continue

        # 命中打点（P0-③，失败不影响链路）
        try:
            import metrics as _m
            _m.inc("alert_sift_silenced_total")
        except Exception as _exc:  # noqa: BLE001
            logger.debug("忽略预期内异常（降级路径）: %s", _exc)
        return True

    return False


def _match_labels(alert: Alert, matchers: dict) -> bool:
    """匹配上下文 = labels + rule_name（rule_name 兼容 alertname/规则名匹配）。"""
    ctx = dict(alert.labels)
    ctx["rule_name"] = alert.rule_name
    ctx["alertname"] = alert.rule_name
    for k, v in matchers.items():
        if ctx.get(k) != v:
            return False
    return True


def _parse_rfc3339(iso_str: str) -> datetime:
    """解析 RFC3339 时间字符串（兼容 Z 后缀）。"""
    return datetime.fromisoformat(iso_str.replace("Z", "+00:00"))


def _within_silence_window(sil: dict, now: datetime) -> bool:
    """判断当前时间是否在静默窗口内。

    优先级：schedule（周期）> starts_at/ends_at（一次性）> 永久。
    """
    schedule = sil.get("schedule")
    if schedule:
        return _within_schedule(schedule, now)

    start = sil.get("starts_at")
    end = sil.get("ends_at")

    if start:
        s = _parse_rfc3339(start)
        if now < s:
            return False

    if end:
        e = _parse_rfc3339(end)
        if now > e:
            return False

    return True


def _within_schedule(schedule: dict, now: datetime) -> bool:
    """判断当前时间是否落在周期性维护窗口内。

    支持跨午夜（end <= start，如 22:00-06:00）。时间按 schedule.timezone 本地化。
    任一配置缺失时保守为不匹配（防止误静默）。
    """
    start_str = schedule.get("start")
    end_str = schedule.get("end")
    if not start_str or not end_str:
        logger.warning("silence schedule 缺 start/end，按不静默处理: %s", schedule)
        return False

    try:
        start_t = _parse_hhmm(start_str)
        end_t = _parse_hhmm(end_str)
    except ValueError:
        logger.warning("silence schedule 时间格式非法（需 HH:MM）: %s", schedule)
        return False

    local = now.astimezone(_tz(schedule.get("timezone")))

    weekdays = _normalize_weekdays(schedule.get("weekdays"))
    if weekdays is not None and local.weekday() not in weekdays:
        return False

    cur = local.time().replace(second=0, microsecond=0)
    if start_t <= end_t:
        return start_t <= cur < end_t
    # 跨午夜窗口：22:00-06:00 → 22:00≤t 或 t<06:00
    return cur >= start_t or cur < end_t


def _tz(tz_name: str | None) -> timezone:
    """按 IANA 名取时区；无/未知时退化为 UTC。"""
    if tz_name and ZoneInfo is not None:
        try:
            return ZoneInfo(tz_name)
        except Exception:
            logger.warning("未知时区 %s，退化 UTC", tz_name)
    return timezone.utc


def _parse_hhmm(s: str) -> time:
    h, m = s.strip().split(":")
    return time(int(h), int(m))


def _normalize_weekdays(weekdays: Any) -> set[int] | None:
    """归一化 weekdays 为 {0..6} 集合；空/缺省返回 None（=每天）。"""
    if weekdays is None or weekdays == "":
        return None
    out: set[int] = set()
    if isinstance(weekdays, (str, int)):
        weekdays = [weekdays]
    for w in weekdays:
        if isinstance(w, int):
            out.add(w % 7)
        else:
            key = str(w).strip().lower()[:3]
            if key in _WEEKDAY_NAMES:
                out.add(_WEEKDAY_NAMES[key])
            else:
                try:
                    out.add(int(key) % 7)
                except ValueError:
                    logger.warning("silence weekdays 非法项 %r，忽略", w)
    return out or None
