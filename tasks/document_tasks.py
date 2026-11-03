"""材料摘要、审批清单规范化与文件绑定。"""
import json
from lab import config
from lab.crypto import sm3_hex
from lab.encoding import MANIFEST_KEYS, HEX64_PATTERN, valid_id
from lab.errors import fail

ID_FIELDS = ("application_id", "student_id", "approver_id",
             "signing_key_id", "request_id")


def _non_negative_int(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _positive_int(value):
    return _non_negative_int(value) and value > 0


def calculate_file_sm3(content: bytes) -> str:
    """计算原始文件字节的 SM3 摘要。

    输入必须为 bytes；不解码、不改换行，不使用 Python 的 hash()。
    返回 64 个小写十六进制字符。类型错误抛 INVALID_INPUT。
    可调用 lab.crypto.sm3_hex。空字节的摘要是合法的，上传限制由提交入口处理。
    """
    if not isinstance(content, bytes):
        fail("INVALID_INPUT")
    return sm3_hex(content)


def canonicalize_manifest(manifest: dict) -> bytes:
    """校验完整审批清单，并生成双方一致的签名字节。
    键集合必须恰好等于MANIFEST_KEYS；schema为aid-approval-v1。
    ID字段使用valid_id；file_sm3须匹配HEX64_PATTERN。
    doc_version是正整数，issued_at是非负整数，bool不能作为整数。
    decision只允许approve或reject。其他字段不能缺失或多出。
    json.dumps使用sort_keys=True、separators=(',', ':')、
    ensure_ascii=False、allow_nan=False，再按UTF-8编码。
    任何格式错误抛INVALID_INPUT，不改变传入字典。
    """
    if not isinstance(manifest, dict) or set(manifest) != MANIFEST_KEYS:
        fail("INVALID_INPUT")
    if manifest["schema"] != "aid-approval-v1":
        fail("INVALID_INPUT")
    for field in ID_FIELDS:
        if not valid_id(manifest[field]):
            fail("INVALID_INPUT")
    file_sm3 = manifest["file_sm3"]
    if not isinstance(file_sm3, str) or HEX64_PATTERN.fullmatch(file_sm3) is None:
        fail("INVALID_INPUT")
    if not _positive_int(manifest["doc_version"]):
        fail("INVALID_INPUT")
    if not _non_negative_int(manifest["issued_at"]):
        fail("INVALID_INPUT")
    decision = manifest["decision"]
    if not isinstance(decision, str) or decision not in ("approve", "reject"):
        fail("INVALID_INPUT")
    try:
        text = json.dumps(manifest, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False)
        return text.encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        fail("INVALID_INPUT")


def build_approval_manifest(application, document, principal, decision, request_id, issued_at):
    """为当前材料版本构造完整审批清单。

    application 含 application_id、student_id、doc_version；document 含
    application_id、version、file_sm3。principal 是已认证主体。
    使用 aid-approval-v1，审批人取 principal.actor_id，密钥标识由
    config.key_id_for(actor_id) 生成（默认模板 '{actor_id}-{algorithm}-01'）。
    其余字段严格对应审批清单的 10 个键。
    不是辅导员抛 FORBIDDEN；文档不属于当前申请或版本不一致抛 VERSION_MISMATCH。
    最后校验清单规范化后返回 dict，不在此处生成签名或判断审批分配。
    """
    if getattr(principal, "role", None) != "counselor":
        fail("FORBIDDEN")
    if document.get("application_id") != application.get("application_id"):
        fail("VERSION_MISMATCH")
    if document.get("version") != application.get("doc_version"):
        fail("VERSION_MISMATCH")
    actor_id = principal.actor_id
    manifest = {
        "schema": "aid-approval-v1",
        "application_id": application.get("application_id"),
        "student_id": application.get("student_id"),
        "doc_version": application.get("doc_version"),
        "file_sm3": document.get("file_sm3"),
        "decision": decision,
        "approver_id": actor_id,
        "signing_key_id": config.key_id_for(actor_id),
        "request_id": request_id,
        "issued_at": issued_at,
    }
    canonicalize_manifest(manifest)
    return manifest


def check_document_binding(manifest, application, document, plaintext):
    """验证签名清单确实对应当前申请和实际材料。

    清单先通过规范化校验。清单、application 和 document 必须指向同一申请。
    student_id必须等于申请所有者；不一致抛DOCUMENT_MISMATCH。
    清单版本、当前版本及document.version不一致抛VERSION_MISMATCH。
    对plaintext重新计算摘要，同时比较清单及document中的file_sm3；
    任一摘要不一致抛DOCUMENT_MISMATCH。成功返回None。
    """
    canonicalize_manifest(manifest)
    if (manifest["application_id"] != application.get("application_id")
            or document.get("application_id") != application.get("application_id")):
        fail("DOCUMENT_MISMATCH")
    if manifest["student_id"] != application.get("student_id"):
        fail("DOCUMENT_MISMATCH")
    if not (manifest["doc_version"] == application.get("doc_version")
            == document.get("version")):
        fail("VERSION_MISMATCH")
    digest = calculate_file_sm3(plaintext)
    if manifest["file_sm3"] != digest or document.get("file_sm3") != digest:
        fail("DOCUMENT_MISMATCH")
    return None
