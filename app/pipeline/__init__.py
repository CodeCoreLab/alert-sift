# -*- coding: utf-8 -*-
"""流水线编排：去重→静默→抑制→分类（→聚合→通知由 main.flush_aggregator 接续）

轻量版（2026-09-04）：LLM 逐条摘要与批量聚类分支已删除（llm.enabled=false 生产恒关）。
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

from models import Alert

logger = logging.getLogger("alert-sift.pipeline")

# 处理标记位
DEDUP_SKIP = "dedup_skip"        # 窗口内重复触发，跳过推送
SILENCED = "silenced"            # 命中静默
INHIBITED = "inhibited"          # 被父告警抑制
AGGREGATED = "aggregated"        # 进入聚合窗口
CLASSIFIED = "classified"        # 已完成分级
NOTIFIED = "notified"            # 已推送


@dataclass
class PipelineResult:
    alert: Alert
    actions: list[str] = field(default_factory=list)
    should_notify: bool = True

    def mark(self, flag: str):
        self.actions.append(flag)

    def has_flag(self, flag: str) -> bool:
        return flag in self.actions

    def blocked(self) -> bool:
        return any(a in (SILENCED, INHIBITED, DEDUP_SKIP) for a in self.actions)


async def run_pipeline(alert: Alert, state) -> PipelineResult:
    """按序执行各处理模块，任一模块 block 则不再往下通知"""
    from pipeline import dedup, silence, inhibit, classify

    # 兼容 FastAPI app.state（Starlette State，属性访问）与测试 dict：
    # 生产传入 app.state（state.cfg / state.store），测试传入 dict（state["cfg"]）。
    # 统一归一为 dict，避免各模块 state.get() 对 State 对象抛 AttributeError。
    if not isinstance(state, dict):
        state = {
            "cfg": getattr(state, "cfg", {}),
            "store": getattr(state, "store", None),
        }

    result = PipelineResult(alert=alert)

    # L2 去重
    if dedup.should_skip(alert, state):
        result.mark(DEDUP_SKIP)
        logger.debug("去重跳过 %s", alert.fingerprint)
        return result

    # L3 静默
    if silence.is_silenced(alert, state):
        result.mark(SILENCED)
        logger.info("静默命中 %s", alert.fingerprint)
        return result

    # L4 抑制（父压子）
    if inhibit.is_inhibited(alert, state):
        result.mark(INHIBITED)
        logger.info("抑制命中 %s", alert.fingerprint)
        return result

    # L6 分类（分级 + 中文规则名 + IP 注入 + 项目路由；同步纯 CPU 操作）
    await asyncio.to_thread(classify.apply, alert, state)
    result.mark(CLASSIFIED)

    return result
