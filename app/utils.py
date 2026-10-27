# -*- coding: utf-8 -*-
"""工具：配置加载 + 日志

重构（2026-08-15）：
  * 提取 _SKIP_FIELDS 为 frozenset 常量（消除重复定义）
  * load_config 增加文件不存在异常处理
  * JsonFormatter 增加字段类型过滤增强
"""
from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any


# logging 内部字段（排除），extra 注入的自定义字段保留
_SKIP_FIELDS = frozenset((
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "taskName", "message", "asctime",
))


def load_config(path: str) -> dict[str, Any]:
    """加载主配置（P1-6 修复：委托 config_loader.load_main 单一入口）。

    本函数保留为向后兼容 API（main/core/admin 直接调用 utils.load_config）。
    """
    from config_loader import load_main
    return load_main(path)


class JsonFormatter(logging.Formatter):
    """结构化 JSON 日志（阶段 1）：ts/level/logger/msg/字段 单行输出。

    开启方式：环境变量 ALERT_SIFT_JSON_LOGS=1。
    """

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(
                timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for k, v in record.__dict__.items():
            if k in _SKIP_FIELDS:
                continue
            if isinstance(v, (str, int, float, bool, type(None))):
                entry[k] = v
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False)


def setup_logging(level: str = "INFO") -> None:
    """配置日志输出格式。"""
    json_logs = os.getenv("ALERT_SIFT_JSON_LOGS") == "1"
    base_fmt = "%(asctime)s %(levelname)s %(name)s: %(message)s"

    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format=base_fmt,
        stream=sys.stdout,
    )

    # 压掉 httpx/httpcore 的 INFO 请求日志：其 message 含完整 URL（会带出 webhook key）
    for _noisy in ("httpx", "httpcore"):
        logging.getLogger(_noisy).setLevel(logging.WARNING)

    # JSON 模式：替换所有 handler 的 formatter
    if json_logs:
        fmt = JsonFormatter()
        for h in logging.root.handlers:
            h.setFormatter(fmt)
