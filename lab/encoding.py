"""严格 JSON 解析与通用数据编码工具。"""
import json
import re
from .errors import fail

ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}\Z")
HEX64_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
MANIFEST_KEYS = frozenset({
    "schema", "application_id", "student_id", "doc_version", "file_sm3",
    "decision", "approver_id", "signing_key_id", "request_id", "issued_at",
})


def valid_id(value):
    return isinstance(value, str) and ID_PATTERN.fullmatch(value) is not None


def json_text(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False)


def strict_json_loads(raw):
    """重复键及NaN/Infinity在进入任务函数前即被拒绝。"""
    def pairs_hook(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                fail("INVALID_INPUT")
            result[key] = value
        return result

    def reject_constant(_):
        fail("INVALID_INPUT")

    try:
        return json.loads(raw, object_pairs_hook=pairs_hook,
                          parse_constant=reject_constant)
    except (ValueError, TypeError, UnicodeError):
        fail("INVALID_INPUT")
