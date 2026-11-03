"""业务授权、签名信任与请求时效。"""
from lab.errors import fail
from .document_tasks import canonicalize_manifest

ALLOWED_ACTIONS = ("access", "read", "submit", "approve", "audit")


def _non_negative_int(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def authorize_action(principal, application, action):
    """按角色、资源和状态判断业务授权，成功返回 None。

    inactive主体一律FORBIDDEN。action允许access/read/submit/approve/audit。
    access和read：学生只能访问本人申请；辅导员只能访问分配给自己的申请；
    finance只能访问APPROVED申请；auditor没有材料访问权。
    submit：本人student，状态DRAFT/SUBMITTED/REJECTED，APPROVED不可更新。
    approve：被分配的counselor，状态SUBMITTED且doc_version>=1。
    audit：只有auditor，application可为空dict。
    角色或资源不符抛FORBIDDEN；提交/审批状态不符抛INVALID_STATE；
    未知action抛INVALID_INPUT。不要将签名有效当作拥有业务权限。
    """
    if not getattr(principal, "active", False):
        fail("FORBIDDEN")
    if not isinstance(action, str) or action not in ALLOWED_ACTIONS:
        fail("INVALID_INPUT")
    if not isinstance(application, dict):
        fail("INVALID_INPUT")
    role = getattr(principal, "role", None)
    actor_id = getattr(principal, "actor_id", None)

    if action in {"access", "read"}:
        if role == "student":
            if application.get("student_id") != actor_id:
                fail("FORBIDDEN")
        elif role == "counselor":
            if application.get("assigned_approver") != actor_id:
                fail("FORBIDDEN")
        elif role == "finance":
            if application.get("status") != "APPROVED":
                fail("FORBIDDEN")
        else:
            fail("FORBIDDEN")
        return None

    if action == "submit":
        if role != "student" or application.get("student_id") != actor_id:
            fail("FORBIDDEN")
        if application.get("status") not in ("DRAFT", "SUBMITTED", "REJECTED"):
            fail("INVALID_STATE")
        return None

    if action == "approve":
        if role != "counselor" or application.get("assigned_approver") != actor_id:
            fail("FORBIDDEN")
        version = application.get("doc_version")
        if (application.get("status") != "SUBMITTED"
                or not isinstance(version, int) or isinstance(version, bool)
                or version < 1):
            fail("INVALID_STATE")
        return None

    if role != "auditor":
        fail("FORBIDDEN")
    return None


def verify_approval_signature(manifest, signature, principal, registry, crypto):
    """将公钥信任与当前审批身份关联，再执行签名验签。

    先规范化清单。审批人必须等于 principal.actor_id，否则
    IDENTITY_MISMATCH。registry 是以 key_id 索引的服务端可信记录 dict。
    未登记或 inactive 密钥抛 UNTRUSTED_KEY；owner_id 不匹配审批人抛
    IDENTITY_MISMATCH。使用记录中的 public_key 调用 crypto.verify；
    False 抛 SIGNATURE_INVALID，密码服务异常原样传播。成功返回 None。
    此函数不检查申请是否分配给该辅导员，分配由 authorize_action 判断。
    """
    data = canonicalize_manifest(manifest)
    if manifest["approver_id"] != getattr(principal, "actor_id", None):
        fail("IDENTITY_MISMATCH")
    record = registry.get(manifest["signing_key_id"]) if isinstance(registry, dict) else None
    if not isinstance(record, dict) or not record.get("active"):
        fail("UNTRUSTED_KEY")
    if record.get("owner_id") != manifest["approver_id"]:
        fail("IDENTITY_MISMATCH")
    if not crypto.verify(record.get("public_key"), data, signature,
                         alg=record.get("alg"), encoding=record.get("encoding")):
        fail("SIGNATURE_INVALID")
    return None


def validate_request_freshness(manifest, now, max_age=300, clock_skew=30):
    """检查首次审批请求的签署时间。

    issued_at 和 now 必须是非负整数，bool 不算整数；配置参数非负整数。
    允许 now-max_age <= issued_at <= now+clock_skew，边界取等可通过。
    类型/参数错误抛 INVALID_INPUT；过旧或过远未来抛 REQUEST_EXPIRED。
    成功返回 None。已处理请求的合法重试在 handle_approval 中先命中去重记录，
    不重新产生业务效果；不能仅靠时间戳代替请求去重。
    """
    if not isinstance(manifest, dict):
        fail("INVALID_INPUT")
    issued_at = manifest.get("issued_at")
    if not all(_non_negative_int(value) for value in
               (issued_at, now, max_age, clock_skew)):
        fail("INVALID_INPUT")
    if issued_at < now - max_age or issued_at > now + clock_skew:
        fail("REQUEST_EXPIRED")
    return None
