# -*- coding: utf-8 -*-
"""alert-sift guard 模块回归测试（审批闭环）

覆盖三个已修复缺陷：
  A13 审批单写入失败仍返回 id      → 写失败必须上抛
  A14 _set_approval 全量读改写 JSONL → 改为追加写 + 跨进程锁，尾部半截行原子修复
  A15 is_approved 完全忽略 params   → 审批匹配必须包含 params 指纹
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from pathlib import Path

# 确保 app 目录可导入
_APP_DIR = Path(__file__).parent
if str(_APP_DIR) not in sys.path:
    sys.path.insert(0, str(_APP_DIR))

import guard


class _ApprovalFileSandbox(unittest.TestCase):
    """把审批文件重定向到临时目录，避免污染仓库 data/ 目录。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="alert_sift_guard_")
        self._orig_file = guard.APPROVAL_FILE
        guard.APPROVAL_FILE = os.path.join(self.tmpdir, "approvals.jsonl")

    def tearDown(self):
        guard.APPROVAL_FILE = self._orig_file
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _raw_lines(self):
        if not os.path.exists(guard.APPROVAL_FILE):
            return []
        with open(guard.APPROVAL_FILE, encoding="utf-8") as f:
            return [ln for ln in f.read().split("\n") if ln.strip()]


# ==================== A13：写入失败必须上抛 ====================
class TestRequestApprovalWriteFailure(_ApprovalFileSandbox):
    def test_write_failure_raises(self):
        """落盘失败时 request_approval 必须抛错，不能返回无效 id。"""
        original = guard._append_approval_records

        def boom(records):
            raise OSError("磁盘满")

        guard._append_approval_records = boom
        try:
            with self.assertRaises(OSError):
                guard.request_approval("rule_upsert", {"file": "x.yaml"}, "ai")
        finally:
            guard._append_approval_records = original

    def test_write_failure_leaves_no_file(self):
        """写失败后不得留下"看起来提交成功"的记录。"""
        original = guard._append_approval_records

        def boom(records):
            raise OSError("permission denied")

        guard._append_approval_records = boom
        try:
            with self.assertRaises(OSError):
                guard.request_approval("silence_delete", {"id": 1}, "ai")
        finally:
            guard._append_approval_records = original
        self.assertEqual(self._raw_lines(), [])

    def test_guarded_propagates_approval_failure(self):
        """guarded 生成审批单失败时必须把异常抛给调用方。"""
        original = guard._append_approval_records

        def boom(records):
            raise OSError("read-only fs")

        guard._append_approval_records = boom

        @guard.guarded("rule_upsert")
        def _tool(**kwargs):
            return {"ok": True}

        try:
            with self.assertRaises(OSError):
                _tool(file="x.yaml")
        finally:
            guard._append_approval_records = original


# ==================== A14：追加写 + 文件锁 ====================
class TestApprovalAppendSemantics(_ApprovalFileSandbox):
    def test_approve_appends_instead_of_rewriting(self):
        """状态变更以追加新行表达，原 pending 行保持不变（不再截断重写）。"""
        aid = guard.request_approval("rule_upsert", {"file": "x.yaml"}, "ai")
        self.assertTrue(guard.approve(aid))

        lines = self._raw_lines()
        self.assertEqual(len(lines), 2, "应追加一条新记录，而不是原地改写")
        first = json.loads(lines[0])
        second = json.loads(lines[1])
        self.assertEqual(first["status"], "pending")
        self.assertEqual(second["status"], "approved")
        self.assertEqual(first["id"], second["id"])

    def test_folded_status_is_latest(self):
        """同一 id 的多条记录折叠后以最后一条为准。"""
        aid = guard.request_approval("rule_upsert", {"file": "x.yaml"}, "ai")
        guard.approve(aid)
        guard.reject(aid)
        rows = guard.list_approvals()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "rejected")
        self.assertEqual(guard.list_approvals("approved"), [])

    def test_concurrent_writes_do_not_lose_records(self):
        """并发追加 + 审批决策不得丢记录（旧实现截断重写会丢）。"""
        n = 40
        ids = []
        errors = []

        def worker(i):
            try:
                aid = guard.request_approval("rule_upsert", {"i": i}, "ai")
                ids.append(aid)
                guard.approve(aid)
            except Exception as e:  # pragma: no cover
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        self.assertEqual(len(ids), n)
        rows = guard.list_approvals()
        self.assertEqual(len(rows), n, "并发下不得丢审批记录")
        self.assertEqual({r["id"] for r in rows}, set(ids))

    def test_concurrent_approve_keeps_other_records(self):
        """一个审批单的决策不得抹掉其它待审批单。"""
        pending = [guard.request_approval("rule_upsert", {"i": i}, "ai")
                   for i in range(10)]
        errors = []

        def worker(aid):
            try:
                guard.approve(aid)
            except Exception as e:  # pragma: no cover
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(a,)) for a in pending]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        rows = guard.list_approvals()
        self.assertEqual(len(rows), 10)
        self.assertTrue(all(r["status"] == "approved" for r in rows))

    def test_torn_tail_is_repaired_atomically(self):
        """文件尾部残留半截行时，追加前应原子修复，不产生更长的坏行。"""
        aid = guard.request_approval("rule_upsert", {"file": "x.yaml"}, "ai")
        with open(guard.APPROVAL_FILE, "a", encoding="utf-8") as f:
            f.write('{"id": "broken", "status": "pen')  # 模拟崩溃留下的半截行

        guard.approve(aid)

        lines = self._raw_lines()
        self.assertEqual(len(lines), 2)
        for ln in lines:
            json.loads(ln)  # 全部可解析

    def test_repair_uses_atomic_replace(self):
        """修复走「临时文件 + os.replace」，不产生遗留的临时文件。"""
        with open(guard.APPROVAL_FILE, "w", encoding="utf-8") as f:
            f.write('{"id": "a"}\n{"id": "b"')
        guard.request_approval("rule_upsert", {"file": "x"}, "ai")
        leftovers = [n for n in os.listdir(os.path.dirname(guard.APPROVAL_FILE))
                     if n.endswith(".repair")]
        self.assertEqual(leftovers, [])


# ==================== A15：审批匹配必须含 params ====================
class TestIsApprovedParamsMatching(_ApprovalFileSandbox):
    def _approve(self, action, params):
        aid = guard.request_approval(action, params, "ai")
        guard.approve(aid)
        return aid

    def test_different_params_not_allowed(self):
        """同一 action、不同参数 → 不得放行。"""
        self._approve("rule_upsert", {"file": "a.yaml"})
        self.assertFalse(guard.is_approved("rule_upsert", {"file": "b.yaml"}))
        self.assertTrue(guard.is_approved("rule_upsert", {"file": "a.yaml"}))

    def test_missing_params_not_allowed(self):
        """审批带参数时，无参数的调用不得被放行。"""
        self._approve("rule_upsert", {"file": "a.yaml"})
        self.assertFalse(guard.is_approved("rule_upsert"))
        self.assertFalse(guard.is_approved("rule_upsert", {}))

    def test_param_order_insensitive(self):
        """参数顺序不同不影响匹配（规范化后比较）。"""
        self._approve("rule_upsert", {"file": "a.yaml", "expr": "x"})
        self.assertTrue(guard.is_approved("rule_upsert", {"expr": "x", "file": "a.yaml"}))

    def test_dry_run_excluded_from_fingerprint(self):
        """dry_run 不改变操作目标，不参与指纹。"""
        self._approve("rule_upsert", {"file": "a.yaml", "dry_run": False})
        self.assertTrue(guard.is_approved("rule_upsert", {"file": "a.yaml"}))

    def test_different_action_not_allowed(self):
        """action 不同 → 不放行。"""
        self._approve("rule_upsert", {"file": "a.yaml"})
        self.assertFalse(guard.is_approved("silence_delete", {"file": "a.yaml"}))

    def test_legacy_record_without_params_is_narrow(self):
        """存量审批记录（无 params 字段）只放行"不约束参数"的调用。"""
        rec = {
            "id": "ap_legacy", "ts": guard.datetime.now(guard.timezone.utc)
            .isoformat(timespec="seconds"),
            "actor": "human", "action": "rule_upsert", "status": "approved",
        }
        with open(guard.APPROVAL_FILE, "w", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        self.assertTrue(guard.is_approved("rule_upsert"))
        self.assertFalse(guard.is_approved("rule_upsert", {"file": "a.yaml"}))

    def test_expired_approval_not_allowed(self):
        """超过有效期的审批单不放行。"""
        old = guard.datetime.now(guard.timezone.utc).isoformat(timespec="seconds")
        rec = {
            "id": "ap_old", "ts": old, "actor": "human", "action": "rule_upsert",
            "params": {"file": "a.yaml"}, "status": "approved",
        }
        with open(guard.APPROVAL_FILE, "w", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        orig_valid = guard.APPROVAL_VALID_SECONDS
        guard.APPROVAL_VALID_SECONDS = -1
        try:
            self.assertFalse(guard.is_approved("rule_upsert", {"file": "a.yaml"}))
        finally:
            guard.APPROVAL_VALID_SECONDS = orig_valid


if __name__ == "__main__":
    unittest.main()
