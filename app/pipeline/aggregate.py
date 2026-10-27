# -*- coding: utf-8 -*-
"""L5 聚合 —— 窗口内按分组键合并为单条通知（防刷屏）（轻量版 2026-09-04）

分组键：project|severity；窗口 60s（config aggregate.window_seconds）。
resolved 与 P0 立即推送，不进聚合窗口。

轻量化（2026-09-04）：
  * 删除外部化路径（external_state/aggregate_queue/CAS 领取）：生产恒为 false
    （单实例 systemd 部署），聚合窗口丢失影响 = 一窗口最多 60s 通知延迟，
    进程内 deque 足够；删除 store 依赖后 Aggregator 不再触碰 SQLite
  * 删除 LLM 聚类分支（llm.enabled=false 生产恒关，且 2026-08-22 实测
    逐条摘要打散聚合窗口致聚类永不触发——模块 cluster.py 已随之废弃）
"""
from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from typing import Any

from models import Alert
from pipeline import PipelineResult, AGGREGATED, NOTIFIED
from pipeline.notify import Notifier
from severity import is_p0 as _is_p0

logger = logging.getLogger("alert-sift.aggregate")

# 分组键分隔符
_GROUP_SEP = "|"


class Aggregator:
    # P0-2 修复（2026-10-05）：聚合队列快照持久化
    # 快照存 store meta（SQLite，崩溃不丢）；TTL = 窗口×4+120s 防僵尸残留。
    # 恢复语义：启动时 recover() 读快照重建队列并重新调度 flush ——
    # 崩溃最多损失「已入队未持久化」的最后一条，其余窗口内告警延迟而非丢失。
    _SNAPSHOT_KEY = "aggregate_queue_snapshot"

    def __init__(self, window: int = 30, notifier_cfg: dict[str, Any] | None = None,
                 cfg: dict[str, Any] | None = None, store: Any = None):
        self.window = window
        self._store = store
        # P1-⑤ 路由树：把顶层 routing（severity_extra_robots）注入 notifier 配置，
        # 供 notify.send_batch 读取（P0 双发值班群）
        full_cfg = cfg or {}
        merged_notifier_cfg = dict(notifier_cfg or {})
        merged_notifier_cfg.setdefault("routing", full_cfg.get("routing", {}))
        self.notifier = Notifier(merged_notifier_cfg)
        self._queue: dict[str, list[PipelineResult]] = defaultdict(list)
        self._lock = asyncio.Lock()
        self._tasks: dict[str, asyncio.Task] = {}

    def _group_key(self, alert: Alert) -> str:
        """构造分组键：project|severity。"""
        return f"{alert.project}{_GROUP_SEP}{alert.severity}"

    async def push_many(self, results: list[PipelineResult]) -> None:
        """批量推送告警到聚合器。"""
        if not results:
            return

        # resolved 与 P0 告警立即推送，不进入聚合窗口
        #  - resolved：恢复通知必须即时（已由 dedup resolved 去抖防刷屏）
        #  - P0：最高优先级，不走 60s 聚合延迟
        immediate: dict[str, list[PipelineResult]] = defaultdict(list)

        for r in results:
            if r.blocked() or not r.should_notify or r.has_flag(NOTIFIED):
                continue
            r.mark(AGGREGATED)

            if r.alert.status == "resolved" or _is_p0(r.alert):
                immediate[self._group_key(r.alert)].append(r)
            else:
                await self.push_one(r)

        for key, batch in immediate.items():
            await self._flush(key, batch)

    async def push_one(self, result: PipelineResult) -> None:
        """单条告警送入聚合窗口，窗口到期后 flush。"""
        key = self._group_key(result.alert)
        async with self._lock:
            self._queue[key].append(result)
            if key not in self._tasks:
                self._tasks[key] = asyncio.create_task(self._flush_after(key))
        self._persist_snapshot()

    def _persist_snapshot(self) -> None:
        """快照当前聚合队列到 store meta（失败静默，不影响主链路）。"""
        if self._store is None:
            return
        try:
            import json as _json
            snap: dict[str, list[dict]] = {}
            for key, results in self._queue.items():
                snap[key] = [r.alert.to_dict() for r in results]
            if snap:
                self._store.set_meta(
                    self._SNAPSHOT_KEY, _json.dumps(snap, ensure_ascii=False),
                    ttl=self.window * 4 + 120)
            else:
                self._store.set_meta(self._SNAPSHOT_KEY, "", ttl=60)
        except Exception as exc:  # noqa: BLE001
            logger.warning("聚合快照写入失败（不影响主链路）: %s", exc)

    async def recover(self) -> int:
        """启动恢复：读快照重建队列并重新调度 flush。返回恢复条数。"""
        if self._store is None:
            return 0
        try:
            import json as _json
            raw = self._store.get_meta(self._SNAPSHOT_KEY)
            if not raw:
                return 0
            snap = _json.loads(raw)
            if not isinstance(snap, dict) or not snap:
                return 0
            n = 0
            async with self._lock:
                for key, alert_dicts in snap.items():
                    batch: list[PipelineResult] = []
                    for d in alert_dicts or []:
                        try:
                            from models import Alert as _Alert
                            a = _Alert(
                                rule_name=d.get("rule_name", ""),
                                labels=d.get("labels", {}) or {},
                                annotations=d.get("annotations", {}) or {},
                                status=d.get("status", "firing"),
                                severity=d.get("severity", "P3"),
                                project=d.get("project", "SYS"),
                                starts_at=d.get("starts_at", ""),
                                fingerprint=d.get("fingerprint", ""),
                                times_fired=int(d.get("times_fired", 1) or 1),
                            )
                            r = PipelineResult(alert=a, should_notify=True)
                            r.mark(AGGREGATED)
                            batch.append(r)
                            n += 1
                        except Exception as exc:  # noqa: BLE001
                            logger.warning("恢复告警失败，跳过: %s", exc)
                    if batch:
                        self._queue[key].extend(batch)
                        if key not in self._tasks:
                            self._tasks[key] = asyncio.create_task(
                                self._flush_after(key))
            if n:
                logger.info("聚合队列崩溃恢复：%d 条告警重新入队（key=%d 组）",
                            n, len(snap))
            self._persist_snapshot()
            return n
        except Exception as exc:  # noqa: BLE001
            logger.warning("聚合队列恢复失败（忽略，按空窗口启动）: %s", exc)
            return 0

    async def _flush_after(self, key: str) -> None:
        """等待窗口到期后执行 flush。"""
        await asyncio.sleep(self.window)
        async with self._lock:
            batch = self._queue.pop(key, [])
            self._tasks.pop(key, None)
        self._persist_snapshot()
        if batch:
            await self._flush(key, batch)

    async def _flush(self, key: str, batch: list[PipelineResult]) -> None:
        """执行聚合推送。"""
        if not batch:
            return

        alerts = [r.alert for r in batch]
        # 聚合信息注入：供模板渲染"已聚合 N 条"
        if len(alerts) > 1:
            firing = [a for a in alerts if a.status == "firing"]
            target = firing[0] if firing else alerts[0]
            target.annotations["aggregated_count"] = f"窗口内聚合 {len(alerts)} 条告警"

        ok = await self.notifier.send_batch(alerts)
        if ok:
            for r in batch:
                r.mark(NOTIFIED)

        metrics_inc(ok, key)
        logger.info("聚合推送 key=%s 告警数=%d 成功=%s", key, len(alerts), ok)


def metrics_inc(ok: bool, key: str) -> None:
    """聚合推送指标打点（轻量，失败不影响链路）。"""
    try:
        import metrics as _m
        _m.inc("alert_sift_aggregate_flush_total", ok=str(ok).lower())
        if ok:
            project = key.split(_GROUP_SEP, 1)[0]
            _m.inc("alert_sift_alerts_pushed_total", project=project)
    except Exception as _exc:  # noqa: BLE001
        logger.debug("忽略预期内异常（降级路径）: %s", _exc)
