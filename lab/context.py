"""装配数据、认证、密码和审计。"""
from pathlib import Path
import time
import uuid
from .auth import Auth
from .crypto import Crypto
from .encoding import json_text, valid_id
from .errors import fail
from .store import Store


class Context:
    def __init__(self, root, clock=None):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.clock = clock or time.time
        self.store = Store(self.root / "server" / "business.sqlite3")
        self.auth = Auth(self.store)
        self.auth.initialize_accounts()
        self.crypto = Crypto(self.root / "private")
        public_rows = [self.crypto.vault.initialize_signer(x) for x in ("T017", "T018")]
        with self.store.transaction() as conn:
            for row in public_rows:
                conn.execute("INSERT OR IGNORE INTO public_keys VALUES(?,?,?,?,?,?)", (
                    row["key_id"], row["owner_id"], row["public_key"], row["active"],
                    row["alg"], row["encoding"]))
            for app_id, student, approver in [
                ("APP-2026-001", "S001", "T017"),
                ("APP-2026-002", "S002", "T018"),
            ]:
                conn.execute("INSERT OR IGNORE INTO applications VALUES(?,?,?,?,?)",
                             (app_id, student, approver, "DRAFT", 0))

    def now(self):
        return int(self.clock())

    def require_principal(self, principal, conn):
        return self.auth.require(principal, conn)

    def audit(self, conn, actor_id, application_id, request_id,
              operation, stage, outcome, error_code=""):
        # 仅允许这些标识与枚举进入日志；从不接收任意extra或材料对象。
        identifiers = [actor_id, application_id, request_id]
        actor_id, application_id, request_id = [
            x if valid_id(x) else "UNKNOWN" for x in identifiers]
        allowed_operations = {"submit", "approve", "read", "audit"}
        allowed_stages = {"input", "authorization", "encrypt", "signature",
                          "binding", "freshness", "idempotency", "commit", "decrypt"}
        if operation not in allowed_operations or stage not in allowed_stages:
            raise ValueError("invalid audit enum")
        if outcome not in {"SUCCESS", "DENIED", "REPLAY"}:
            raise ValueError("invalid audit result")
        if error_code and (not isinstance(error_code, str) or
                           not error_code.replace("_", "").isalnum() or len(error_code) > 40):
            error_code = "INTERNAL_ERROR"
        conn.execute("INSERT INTO audit_events(occurred_at,actor_id,application_id,"
                     "request_id,operation,stage,outcome,error_code) VALUES(?,?,?,?,?,?,?,?)",
                     (self.now(), actor_id, application_id, request_id,
                      operation, stage, outcome, error_code))

    def record_failure(self, principal, app_id, request_id, operation, stage, error):
        # 在业务事务回滚并关闭之后写拒绝事件，避免拒绝日志随事务消失。
        actor_id = getattr(principal, "actor_id", "UNKNOWN")
        with self.store.transaction() as conn:
            self.audit(conn, actor_id, app_id, request_id, operation,
                       stage, "DENIED", error.code)

    def metadata(self, application, version):
        return {"application_id": application["application_id"],
                "student_id": application["student_id"], "doc_version": version}

    def prepare_approval(self, principal, app_id, decision="approve", request_id=None):
        """模拟辅导员终端确认当前版本后签署；签名值不持久化到客户端日志。"""
        from tasks.access_tasks import authorize_action
        from tasks.document_tasks import build_approval_manifest, canonicalize_manifest
        with self.store.connect() as conn:
            self.require_principal(principal, conn)
            application = self.store.app(conn, app_id)
            authorize_action(principal, application, "approve")
            document = self.store.document(conn, app_id, application["doc_version"])
        manifest = build_approval_manifest(
            application, document, principal, decision,
            request_id or "APR-" + uuid.uuid4().hex, self.now())
        signature = self.crypto.sign(principal.actor_id, manifest["signing_key_id"],
                                     canonicalize_manifest(manifest))
        return manifest, signature

    def list_applications(self, principal):
        with self.store.connect() as conn:
            self.require_principal(principal, conn)
            rows = [dict(x) for x in conn.execute("SELECT * FROM applications")]
        if principal.role == "student":
            return [a for a in rows if a["student_id"] == principal.actor_id]
        if principal.role == "counselor":
            return [a for a in rows if a["assigned_approver"] == principal.actor_id]
        if principal.role == "finance":
            return [a for a in rows if a["status"] == "APPROVED"]
        if principal.role == "auditor":
            return rows  # 这里只包含标识、状态和版本，没有附件原文。
        fail("FORBIDDEN")

    def audit_events(self, principal):
        from tasks.access_tasks import authorize_action
        with self.store.connect() as conn:
            self.require_principal(principal, conn)
            authorize_action(principal, {}, "audit")
            return [dict(x) for x in conn.execute(
                "SELECT * FROM audit_events ORDER BY event_id DESC LIMIT 100")]
