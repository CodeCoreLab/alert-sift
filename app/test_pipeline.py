# -*- coding: utf-8 -*-
"""alert-sift pipeline 模块单元测试

覆盖：classify / dedup / silence / inhibit / notify / aggregate + 轻量化回归
正常路径 + 异常路径，确保重构不引入新 Bug。
"""
from __future__ import annotations

import sys
import time
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
from pathlib import Path

# 确保 app 目录可导入
_APP_DIR = Path(__file__).parent.parent / "app"
if str(_APP_DIR) not in sys.path:
    sys.path.insert(0, str(_APP_DIR))

from models import Alert
import logging


logger = logging.getLogger(__name__)


# ==================== 测试工具 ====================
def _make_alert(**overrides) -> Alert:
    """工厂方法：创建测试用 Alert 对象。

    注意：rule_name 属性与 labels["alertname"] 保持同步，
    避免静默/抑制匹配（匹配上下文用 rule_name 属性）时数据不一致。
    """
    rule_name = overrides.get("rule_name", "TestRule")
    labels = {
        "alertname": rule_name,
        "instance": "192.0.2.1",
        "hostname": "test-host",
        "ip": "192.0.2.1",
        "type": "host",
    }
    labels.update(overrides.get("labels", {}))
    annotations = {
        "summary": "Test summary",
        "description": "Test description",
    }
    annotations.update(overrides.get("annotations", {}))
    return Alert(
        rule_name=rule_name,
        labels=labels,
        annotations=annotations,
        status=overrides.get("status", "firing"),
        severity=overrides.get("severity", ""),
        project=overrides.get("project", "SYS"),
        fingerprint=overrides.get("fingerprint", "test_fp_001"),
    )


def _make_state(cfg: dict | None = None, store: MagicMock | None = None) -> dict:
    """工厂方法：创建测试用 state 字典。"""
    return {
        "cfg": cfg or {},
        "store": store or MagicMock(),
    }


# ==================== 测试：classify ====================
class TestClassify(unittest.TestCase):
    """L6 分类模块测试。"""

    def test_severity_from_type(self):
        """type=host → severity=P2"""
        from pipeline.classify import apply
        alert = _make_alert(labels={"type": "host"})
        state = _make_state()
        apply(alert, state)
        self.assertEqual(alert.severity, "P2")

    def test_severity_from_type_disk(self):
        """type=disk → severity=P1"""
        from pipeline.classify import apply
        alert = _make_alert(labels={"type": "disk"})
        state = _make_state()
        apply(alert, state)
        self.assertEqual(alert.severity, "P1")

    def test_severity_from_type_biz(self):
        """type=biz → severity=P0"""
        from pipeline.classify import apply
        alert = _make_alert(labels={"type": "biz"})
        state = _make_state()
        apply(alert, state)
        self.assertEqual(alert.severity, "P0")

    def test_severity_not_overwritten(self):
        """显式 severity 不被覆盖"""
        from pipeline.classify import apply
        alert = _make_alert(severity="P1", labels={"type": "host"})
        state = _make_state()
        apply(alert, state)
        self.assertEqual(alert.severity, "P1")

    def test_project_mapping(self):
        """IP 前缀 → project 映射（project_mapping 配置）"""
        from pipeline.classify import apply
        alert = _make_alert(
            project="SYS",
            labels={"ip": "192.0.2.10", "instance": "192.0.2.10"}
        )
        state = _make_state(cfg={
            "project_mapping": [
                {"project": "APP", "ip_prefixes": ["192.0.2."]},
                {"project": "OPS", "ip_prefixes": ["203.0.113."]},
            ]
        })
        apply(alert, state)
        self.assertEqual(alert.project, "APP")

    def test_project_no_ip(self):
        """IP 为空时返回 SYS"""
        from pipeline.classify import apply
        alert = _make_alert(project="SYS", labels={"ip": "", "instance": ""})
        state = _make_state()
        apply(alert, state)
        self.assertEqual(alert.project, "SYS")

    def test_default_severity_unknown_type(self):
        """未知 type → P3"""
        from pipeline.classify import _default_severity
        self.assertEqual(_default_severity("unknown"), "P3")

    def test_severity_label_sync(self):
        """severity 同步到 labels"""
        from pipeline.classify import apply
        alert = _make_alert(labels={"type": "host"})
        state = _make_state()
        apply(alert, state)
        self.assertEqual(alert.labels.get("severity"), "P2")


# ==================== 测试：dedup ====================
class TestDedup(unittest.TestCase):
    """L2 去重模块测试。"""

    def test_resolved_never_skipped(self):
        """resolved 事件永不跳过"""
        from pipeline.dedup import should_skip
        alert = _make_alert(status="resolved")
        state = _make_state()
        state["store"].get_meta.return_value = None
        self.assertFalse(should_skip(alert, state))

    def test_short_window_skip(self):
        """短窗口内同指纹应跳过"""
        from pipeline.dedup import should_skip
        alert = _make_alert()
        now = time.time()
        state = _make_state()
        state["store"].get_meta.side_effect = lambda k: now if k.startswith("dedup:") else None
        self.assertTrue(should_skip(alert, state))

    def test_long_window_skip(self):
        """长窗口内且非 P0 应跳过"""
        from pipeline.dedup import should_skip
        alert = _make_alert(severity="P1")
        # P1 fallback 窗口=3600s，用半小时前避开 3600s 边界浮点误差
        old = time.time() - 1800
        state = _make_state()
        state["store"].get_meta.side_effect = lambda k: old if k.startswith("repeat:") else None
        self.assertTrue(should_skip(alert, state))

    def test_p0_long_window_not_skipped(self):
        """P0 长窗口豁免"""
        from pipeline.dedup import should_skip
        alert = _make_alert(severity="P0")
        _unused_bind = str(time.time() - 3600)  # noqa: F841 —— 原变量 old
        state = _make_state()
        state["store"].get_meta.side_effect = lambda k: old if k.startswith("repeat:") else None
        self.assertFalse(should_skip(alert, state))

    def test_biz_type_p0_not_skipped(self):
        """type=biz 视为 P0 豁免"""
        from pipeline.dedup import should_skip
        alert = _make_alert(labels={"type": "biz"})
        _unused_bind = str(time.time() - 3600)  # noqa: F841 —— 原变量 old
        state = _make_state()
        state["store"].get_meta.side_effect = lambda k: old if k.startswith("repeat:") else None
        self.assertFalse(should_skip(alert, state))

    def test_parse_ts_none(self):
        """None 值返回 None"""
        from pipeline.dedup import _parse_ts
        self.assertIsNone(_parse_ts(None))

    def test_parse_ts_string(self):
        """字符串正常解析"""
        from pipeline.dedup import _parse_ts
        self.assertEqual(_parse_ts("1234.5"), 1234.5)

    def test_parse_ts_invalid(self):
        """脏数据返回 None"""
        from pipeline.dedup import _parse_ts
        self.assertIsNone(_parse_ts("invalid"))


# ==================== 测试：silence ====================
class TestSilence(unittest.TestCase):
    """L3 静默模块测试。"""

    def test_no_silences(self):
        """无静默规则 → 不静默"""
        from pipeline.silence import is_silenced
        alert = _make_alert()
        state = _make_state(cfg={})
        self.assertFalse(is_silenced(alert, state))

    def test_match_labels(self):
        """匹配规则 → 静默"""
        from pipeline.silence import is_silenced
        alert = _make_alert(rule_name="NoiseRule")
        state = _make_state(cfg={
            "silences": [
                {
                    "matchers": {"rule_name": "NoiseRule"},
                    "starts_at": "2020-01-01T00:00:00Z",
                    "ends_at": "2030-01-01T00:00:00Z",
                }
            ]
        })
        self.assertTrue(is_silenced(alert, state))

    def test_expired_silence(self):
        """过期静默 → 不静默"""
        from pipeline.silence import is_silenced
        alert = _make_alert(rule_name="OldRule")
        state = _make_state(cfg={
            "silences": [
                {
                    "matchers": {"rule_name": "OldRule"},
                    "starts_at": "2020-01-01T00:00:00Z",
                    "ends_at": "2021-01-01T00:00:00Z",
                }
            ]
        })
        self.assertFalse(is_silenced(alert, state))

    def test_future_silence(self):
        """未来开始的静默 → 不静默"""
        from pipeline.silence import is_silenced
        alert = _make_alert(rule_name="FutureRule")
        state = _make_state(cfg={
            "silences": [
                {
                    "matchers": {"rule_name": "FutureRule"},
                    "starts_at": "2030-01-01T00:00:00Z",
                }
            ]
        })
        self.assertFalse(is_silenced(alert, state))

    def test_schedule_weekday_in_window(self):
        """周期窗口：工作日 18:00-19:00 CST 命中"""
        from pipeline.silence import _within_schedule
        sched = {"timezone": "Asia/Shanghai",
                 "weekdays": ["mon", "tue", "wed", "thu", "fri"],
                 "start": "18:00", "end": "19:00"}
        now = datetime(2026, 8, 17, 18, 30, tzinfo=timezone(timedelta(hours=8))).astimezone(timezone.utc)
        self.assertTrue(_within_schedule(sched, now))

    def test_schedule_weekday_out_of_window(self):
        """周期窗口：17:59 未到 18:00，不命中"""
        from pipeline.silence import _within_schedule
        sched = {"timezone": "Asia/Shanghai", "weekdays": ["mon"], "start": "18:00", "end": "19:00"}
        now = datetime(2026, 8, 17, 17, 59, tzinfo=timezone(timedelta(hours=8))).astimezone(timezone.utc)
        self.assertFalse(_within_schedule(sched, now))

    def test_schedule_wrong_weekday(self):
        """周期窗口：周日同时间不命中（weekdays 过滤）"""
        from pipeline.silence import _within_schedule
        sched = {"timezone": "Asia/Shanghai", "weekdays": ["mon"], "start": "18:00", "end": "19:00"}
        now = datetime(2026, 8, 16, 18, 30, tzinfo=timezone(timedelta(hours=8))).astimezone(timezone.utc)
        self.assertFalse(_within_schedule(sched, now))

    def test_schedule_cross_midnight(self):
        """周期窗口：跨午夜 22:00-06:00，凌晨 03:00 命中、午后 12:00 不命中"""
        from pipeline.silence import _within_schedule
        sched = {"timezone": "Asia/Shanghai", "start": "22:00", "end": "06:00"}
        now_in = datetime(2026, 8, 17, 3, 0, tzinfo=timezone(timedelta(hours=8))).astimezone(timezone.utc)
        now_out = datetime(2026, 8, 17, 12, 0, tzinfo=timezone(timedelta(hours=8))).astimezone(timezone.utc)
        self.assertTrue(_within_schedule(sched, now_in))
        self.assertFalse(_within_schedule(sched, now_out))

    def test_schedule_missing_time(self):
        """周期窗口缺 start/end → 不命中（保守）"""
        from pipeline.silence import _within_schedule
        self.assertFalse(_within_schedule({"weekdays": ["mon"]}, datetime.now(timezone.utc)))

    def test_match_by_rule_name(self):
        """rule_name 匹配"""
        from pipeline.silence import _match_labels
        alert = _make_alert(labels={"alertname": "TestRule"})
        matchers = {"rule_name": "TestRule"}
        self.assertTrue(_match_labels(alert, matchers))


# ==================== 测试：inhibit ====================
class TestInhibit(unittest.TestCase):
    """L4 抑制模块测试。"""

    def test_no_inhibits(self):
        """无抑制规则 → 不抑制"""
        from pipeline.inhibit import is_inhibited
        alert = _make_alert()
        state = _make_state(cfg={})
        self.assertFalse(is_inhibited(alert, state))

    def test_resolved_not_inhibited(self):
        """resolved 不抑制"""
        from pipeline.inhibit import is_inhibited
        alert = _make_alert(status="resolved")
        state = _make_state(cfg={"inhibits": [{}]})
        self.assertFalse(is_inhibited(alert, state))

    def test_inhibition(self):
        """主机宕机抑制子告警"""
        from pipeline.inhibit import is_inhibited
        # 子告警：CPU 高
        child = _make_alert(
            rule_name="HighCPU",
            labels={"instance": "192.0.2.1", "ip": "192.0.2.1"}
        )
        # 父告警：主机宕机
        parent_data = {
            "rule_name": "HostDown",
            "labels": {"instance": "192.0.2.1", "ip": "192.0.2.1"},
            "status": "firing",
            "fingerprint": "parent_fp",
        }

        mock_store = MagicMock()
        mock_store.get_active_alerts.return_value = [parent_data]
        state = _make_state(cfg={
            "inhibits": [
                {
                    "source_matchers": {"rule_name": "HighCPU"},
                    "target_matchers": {"rule_name": "HostDown"},
                    "equal": ["instance"],
                }
            ]
        })
        state["store"] = mock_store
        self.assertTrue(is_inhibited(child, state))

    def test_no_inhibition_different_instance(self):
        """不同 instance 不抑制"""
        from pipeline.inhibit import is_inhibited
        child = _make_alert(
            rule_name="HighCPU",
            labels={"instance": "192.0.2.2", "ip": "192.0.2.2"}
        )
        parent_data = {
            "rule_name": "HostDown",
            "labels": {"instance": "192.0.2.1", "ip": "192.0.2.1"},
            "status": "firing",
            "fingerprint": "parent_fp",
        }

        mock_store = MagicMock()
        mock_store.get_active_alerts.return_value = [parent_data]
        state = _make_state(cfg={
            "inhibits": [
                {
                    "source_matchers": {"rule_name": "HighCPU"},
                    "target_matchers": {"rule_name": "HostDown"},
                    "equal": ["instance"],
                }
            ]
        })
        state["store"] = mock_store
        self.assertFalse(is_inhibited(child, state))


# ==================== 测试：sqlite_store ====================
class TestSQLiteStore(unittest.TestCase):
    """SQLite 存储层测试。"""

    def setUp(self):
        self.db_path = "/tmp/test_alert_sift.db"
        from store.sqlite_store import SQLiteStore
        self.store = SQLiteStore(self.db_path)
        self.store.init()

    def tearDown(self):
        self.store.close()
        import os
        try:
            os.remove(self.db_path)
        except OSError:
            logger.warning(
                "已忽略异常并继续（原为静默 pass，调用点见本行）",
                exc_info=True,
            )

    def test_upsert_and_get_active(self):
        """插入并获取活跃告警"""
        alert = _make_alert()
        self.store.upsert_active(alert)
        rows = self.store.get_active_alerts()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["fingerprint"], alert.fingerprint)

    def test_remove_active(self):
        """移除活跃告警"""
        alert = _make_alert()
        self.store.upsert_active(alert)
        self.store.remove_active(alert.fingerprint)
        rows = self.store.get_active_alerts()
        self.assertEqual(len(rows), 0)

    def test_meta_set_get(self):
        """meta KV 读写"""
        self.store.set_meta("test_key", "test_value", ttl=300)
        val = self.store.get_meta("test_key")
        self.assertEqual(val, "test_value")

    def test_meta_incr(self):
        """meta 自增"""
        v1 = self.store.incr_meta("counter")
        v2 = self.store.incr_meta("counter")
        self.assertEqual(v1, 1)
        self.assertEqual(v2, 2)

    def test_meta_expire(self):
        """meta 过期自动清理"""
        self.store.set_meta("expire_key", "value", ttl=0)
        # ttl=0 表示立即过期
        import time
        time.sleep(0.01)
        val = self.store.get_meta("expire_key")
        self.assertIsNone(val)

    def test_add_history_batch(self):
        """批量历史写入"""
        alerts = [_make_alert(fingerprint=f"fp_{i}") for i in range(5)]
        self.store.add_history_batch(alerts)
        stats = self.store.conn.execute(
            "SELECT COUNT(*) FROM alert_history"
        ).fetchone()[0]
        self.assertEqual(stats, 5)

    def test_empty_get_active_alerts(self):
        """空表返回空列表"""
        rows = self.store.get_active_alerts()
        self.assertEqual(rows, [])


# ==================== 测试：utils ====================
class TestUtils(unittest.TestCase):
    """工具函数测试。"""

    def test_load_config_missing_file(self):
        """不存在的配置文件返回空字典"""
        from utils import load_config
        result = load_config("/nonexistent/path.yaml")
        self.assertEqual(result, {})

    def test_json_formatter_fields(self):
        """JsonFormatter 排除内部字段"""
        from utils import _SKIP_FIELDS
        self.assertIn("name", _SKIP_FIELDS)
        self.assertIn("msg", _SKIP_FIELDS)
        self.assertIn("levelname", _SKIP_FIELDS)


# ==================== 测试：metrics ====================
class TestMetrics(unittest.TestCase):
    """指标系统测试。"""

    def setUp(self):
        # 清空计数器
        import metrics as m
        m._COUNTERS.clear()
        m._GAUGES.clear()

    def test_inc(self):
        """计数器递增"""
        import metrics as m
        m.inc("test_counter", value=1)
        m.inc("test_counter", value=1)
        rendered = m.render()
        self.assertIn("test_counter", rendered)
        self.assertIn("2", rendered)

    def test_set_gauge(self):
        """仪表设置"""
        import metrics as m
        m.set_gauge("test_gauge", 42.0)
        rendered = m.render()
        self.assertIn("test_gauge", rendered)
        self.assertIn("42", rendered)

    def test_render_empty(self):
        """空数据返回空字符串"""
        import metrics as m
        m._COUNTERS.clear()
        m._GAUGES.clear()
        self.assertEqual(m.render(), "")

    def test_inc_empty_name(self):
        """空 name 不报错"""
        import metrics as m
        m.inc("")  # 不应抛出异常


# ==================== 测试：轻量化回归（2026-09-04） ====================
class TestLightweightRefactor(unittest.TestCase):
    """轻量化重构回归：LLM 分支删除后链路行为不变。"""

    def test_cluster_module_removed(self):
        """cluster.py / llm_utils.py / llm_advisor.py / enhanced_alert_card.py 已删除，import 应失败"""
        import importlib
        self.assertRaises(ModuleNotFoundError, importlib.import_module, "pipeline.cluster")
        self.assertRaises(ModuleNotFoundError, importlib.import_module, "pipeline.llm_utils")
        self.assertRaises(ModuleNotFoundError, importlib.import_module, "pipeline.llm_advisor")
        self.assertRaises(ModuleNotFoundError, importlib.import_module, "pipeline.enhanced_alert_card")

    def test_aggregator_no_external(self):
        """Aggregator 不再接受 external 参数（store 已被 10-05 P0-2 快照持久化合法复用）"""
        import inspect
        from pipeline.aggregate import Aggregator
        sig = inspect.signature(Aggregator.__init__)
        self.assertNotIn("external", sig.parameters)

    def test_pipeline_end_to_end_normal_alert(self):
        """正常告警全链路：dedup 未命中 → silence 未命中 → inhibit 未命中 → classify 完成"""
        import asyncio
        from pipeline import run_pipeline, CLASSIFIED
        alert = _make_alert()
        state = _make_state()
        state["store"].get_meta.return_value = None
        state["store"].get_active_alerts.return_value = []
        result = asyncio.get_event_loop().run_until_complete(run_pipeline(alert, state))
        self.assertTrue(result.has_flag(CLASSIFIED))
        self.assertFalse(result.blocked())
        self.assertEqual(alert.severity, "P2")  # type=host 兜底
        self.assertEqual(alert.rule_cn, "")  # 裸名未登记 → 空串，模板回退 summary

    def test_rule_cn_memleak(self):
        """MemLeak → 内存泄漏"""
        from pipeline.classify import _rule_cn
        self.assertEqual(_rule_cn("SYS|Host|P3|MemLeak"), "SYS·主机·内存泄漏")

    def test_storm_fold_still_works(self):
        """风暴折叠保留：超限后应跳过（内存 dict 模拟 meta）"""
        from pipeline.dedup import _storm_folded
        alert = _make_alert(rule_name="StormRule", fingerprint="storm_fp")
        kv: dict = {}
        store = MagicMock()
        store.get_meta.side_effect = lambda k: kv.get(k)
        store.set_meta.side_effect = lambda k, v, ttl=None: kv.update({k: v})
        state = _make_state(cfg={"dedup": {"storm_limit": 2}})
        state["store"] = store
        now = time.time()
        # 前 2 次正常（<=limit），第 3 次折叠
        self.assertFalse(_storm_folded(alert, state, now))
        self.assertFalse(_storm_folded(alert, state, now))
        self.assertTrue(_storm_folded(alert, state, now))


if __name__ == "__main__":
    unittest.main()
