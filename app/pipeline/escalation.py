"""P1-1 修复（2026-10-05）：升级引擎独立成模块。

原状态（main.py 内嵌 _escalation_loop）：
  * 30s 循环全表扫 active_alerts
  * 升级成功才写 meta、失败靠下轮重试（非真重试）
  * ack 宽限期硬编码 30min
  * fingerprint 用旧算法（P0-1 修复后未同步）
  * 消息格式与主链路重复

改造：
  * 抽出 EscalationEngine 类，与 notify 同级模块
  * 使用 stable_fingerprint（P0-1 联动）
  * 升级消息复用 notify._friendly_name 友好化
  * ack 宽限期可配置（config escalation.ack_grace_seconds）
  * 提供 run_once() 便于单测与手工触发
"""
from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime

import httpx

import metrics
from pipeline.notify import _friendly_name, _safe_url, _scrub




def _to_int(value, ctx=""):
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"非法整数{(' ' + ctx) if ctx else ''}: {value!r}") from exc

logger = logging.getLogger("alert-sift.escalation")

DEFAULT_ACK_GRACE_SECONDS = 1800  # ack 后 30min 宽限期（默认，可配置覆盖）


def _parse_ts(iso_str: str) -> float | None:
    """ISO starts_at → epoch 秒；解析失败返回 None。"""
    if not iso_str:
        return None
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.timestamp()
    except Exception:  # noqa: BLE001
        return None


def _parse_ts_meta(ctx, key: str) -> float | None:
    """读取 meta 时间戳；脏数据/None 安全。"""
    try:
        raw = ctx.store.get_meta(key)
        if raw is None:
            return None
        return float(raw)
    except (TypeError, ValueError):
        return None


def _fmt_ts(iso_str: str) -> str:
    """ISO 时间 → MM-DD HH:MM 展示格式。"""
    if not iso_str:
        return "N/A"
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.strftime("%m-%d %H:%M")
    except Exception:  # noqa: BLE001
        return iso_str[:16].replace("T", " ")


class EscalationEngine:
    """升级策略引擎（FSM triggered→ack→escalation）。

    声明式配置（config.yaml escalation.policies，按 severity 分级）：
        P0: [{level:1, after_seconds:300, notify:[SYS]}, {level:2, after_seconds:900}]
        P1: [{level:1, after_seconds:1800, notify:[SYS]}]

    行为：
        * 活跃告警（firing/ack）按 starts_at 已持续时长匹配策略等级
        * 匹配但未升级过（meta esc:{stable_fp}:{level} 不存在）→ 推送 + 记 meta 防重复
        * ack 宽限期内不升级（config escalation.ack_grace_seconds，默认 1800）
        * 推送失败不写 meta，下轮自动重试
    """

    def __init__(self, cfg: dict, resolved_robots: dict[str, str]):
        self.cfg = cfg
        self.resolved_robots = resolved_robots
        esc_cfg = cfg.get("escalation", {})
        self.policies: dict[str, list] = esc_cfg.get("policies", {})
        self.ack_grace_seconds: int = _to_int(
            esc_cfg.get("ack_grace_seconds", DEFAULT_ACK_GRACE_SECONDS))

    async def _notify_upgrade(self, alert: dict, level: dict, sev: str) -> bool:
        """推送升级通知到指定机器人（企微 markdown，带重试）。

        Returns:
            True=至少一个 target 推送成功；False=全部失败。
            仅 True 时上层记 esc meta，避免失败后该等级升级通知永久丢失。
        """
        lvl = level.get("level", 1)
        msg_tpl = level.get("message") or ("已持续超时未确认，升级至第 %d 级" % lvl)
        labels = alert.get("labels") or {}
        host = labels.get("hostname") or labels.get("instance") or labels.get("ip") or "N/A"
        friendly = _friendly_name(alert.get("rule_name", "unknown"))
        msg = (
            "\U0001f6a8 **告警升级提醒**【%s】\n"
            "> **规则**：%s\n"
            "> **主机**：%s\n"
            "> **开始**：%s\n"
            "> **提示**：%s\n"
            "> **fingerprint**：`%s`"
        ) % (
            sev, friendly, host,
            _fmt_ts(alert.get("starts_at")), msg_tpl,
            str(alert.get("fingerprint", ""))[:12],
        )
        payload = {"msgtype": "markdown", "markdown": {"content": msg}}
        targets = level.get("notify") or ["SYS"]
        ok_any = False
        for proj in targets:
            url = self.resolved_robots.get(proj)
            if not url:
                logger.warning("升级通知 project=%s 无机器人，跳过", proj)
                continue
            for attempt in range(3):
                try:
                    async with httpx.AsyncClient(timeout=10) as client:
                        resp = await client.post(url, json=payload)
                    if resp.status_code == 200 and resp.json().get("errcode") == 0:
                        metrics.inc("alert_sift_escalation_total",
                                    severity=sev, level=str(lvl))
                        logger.info("升级通知已推送 project=%s fp=%s lvl=%s",
                                    proj, str(alert.get("fingerprint", ""))[:12], lvl)
                        ok_any = True
                        break
                    logger.error("升级推送失败 status=%s body=%s",
                                 resp.status_code, resp.text[:200])
                    break
                except Exception as exc:  # noqa: BLE001
                    if attempt < 2:
                        await asyncio.sleep([1, 3][attempt])
                    else:
                        # P1-3（2026-10-30）：当前行为是直接打印 exc，
                        # 而 httpx 的部分异常会把请求 URL 原文（含企微 webhook
                        # 的 key= 凭据）写进 str(exc) ⇒ 日志泄露凭据。
                        # 改法：异常文本先过 _scrub 脱敏。
                        logger.error("升级推送最终失败 proj=%s url=%s: %s",
                                     proj, _safe_url(url), _scrub(str(exc), url))
        if not ok_any:
            logger.error("升级通知全部 target 失败 fp=%s lvl=%s（不记 esc meta，下轮重试）",
                         str(alert.get("fingerprint", ""))[:12], lvl)
        return ok_any

    async def run_once(self, ctx) -> int:
        """单次扫描执行升级；返回本轮推送成功的升级数。"""
        now = time.time()
        notified = 0
        try:
            for alert in ctx.get_firing_alerts():
                sev = alert.get("severity", "P3")
                policy_list = self.policies.get(sev)
                if not policy_list:
                    continue
                # P0-1 修复：使用 stable_fingerprint 做 meta key
                stable_fp = alert.get("stable_fingerprint") or alert.get("fingerprint", "")
                start_ts = _parse_ts(alert.get("starts_at", ""))
                if start_ts is None:
                    continue
                elapsed = now - start_ts

                # ack 宽限期（P0-1：meta key 用 stable_fingerprint）
                acked_ts = _parse_ts_meta(ctx, f"acked:{stable_fp}")
                if acked_ts is not None and (now - acked_ts) < self.ack_grace_seconds:
                    continue

                for level in policy_list:
                    if elapsed < level.get("after_seconds", 0):
                        break  # 策略按 after_seconds 升序
                    lvl = level.get("level", 1)
                    esc_key = f"esc:{stable_fp}:{lvl}"
                    if ctx.store.get_meta(esc_key) is not None:
                        continue  # 该等级已升级过
                    if await self._notify_upgrade(alert, level, sev):
                        try:
                            ctx.store.set_meta(esc_key, str(now), ttl=86400)
                        except Exception as _exc:  # noqa: BLE001
                            logger.debug("忽略预期内异常（降级路径）: %s", _exc)
                        notified += 1
        except Exception as exc:  # noqa: BLE001
            logger.warning("升级引擎扫描异常（跳过）: %s", exc)
        return notified
