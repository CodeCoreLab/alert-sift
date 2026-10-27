# -*- coding: utf-8 -*-
"""alert-sift — 告警降噪网关

接收 vmalert / Alertmanager 的 webhook 告警，经
去重 → 静默 → 抑制 → 聚合 → 分类 → 通知 流水线降噪后路由推送。
"""

__version__ = "0.1.0"
