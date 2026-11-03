"""测试入口：运行 tests/ 下的全部用例，失败时以非零退出码退出。"""
from pathlib import Path
import json
import os
import sys
import unittest

# 既有回归用例（50 个 + 密码敏捷性回归）以 SM2 世界为断言基准（硬编码
# T017-SM2-01、Hex 签名等）。系统默认已切换为 ML-DSA-65，因此测试入口把
# 既有套件钉在 SM2 上运行；ML-DSA 行为由 tests/test_ml_dsa.py 显式覆盖。
# 显式设置 AID_SIGNING_ALGORITHM 可覆盖此钉住值。
os.environ.setdefault("AID_SIGNING_ALGORITHM", "SM2")

ROOT = Path(__file__).resolve().parent


def run(pattern="test_*.py", report=True):
    suite = unittest.defaultTestLoader.discover(
        str(ROOT / "tests"), pattern=pattern, top_level_dir=str(ROOT))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    summary = {"tests_run": result.testsRun, "failures": len(result.failures),
               "errors": len(result.errors), "skipped": len(result.skipped),
               "successful": result.wasSuccessful(),
               "failed_cases": [case.id() for case, _ in result.failures],
               "error_cases": [case.id() for case, _ in result.errors]}
    if report:
        target = ROOT / "runtime" / "test_reports" / "latest_result.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
        print("\n测试摘要：", target)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run())
