"""本机演示账号环境：口令校验后签发随机会话令牌。"""
from dataclasses import dataclass, field
import hashlib
import hmac
import secrets
from .errors import fail

DEMO_PASSWORD = "Lab2026!"
PBKDF2_ROUNDS = 260_000
ACCOUNTS = {
    "S001": "student", "S002": "student", "T017": "counselor",
    "T018": "counselor", "F001": "finance", "A001": "auditor",
}


@dataclass(frozen=True)
class Principal:
    actor_id: str
    role: str
    active: bool = True
    token: str = field(default="", repr=False)


def password_digest(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                               bytes.fromhex(salt), PBKDF2_ROUNDS).hex()


class Auth:
    def __init__(self, store):
        self.store = store
        self._sessions = {}

    def initialize_accounts(self):
        with self.store.transaction() as conn:
            for actor_id, role in ACCOUNTS.items():
                if conn.execute("SELECT 1 FROM users WHERE actor_id=?",
                                (actor_id,)).fetchone():
                    continue
                salt = secrets.token_hex(16)
                conn.execute("INSERT INTO users VALUES(?,?,?,?,?)", (
                    actor_id, role, 1, salt, password_digest(DEMO_PASSWORD, salt)))

    def login(self, actor_id, password):
        if not isinstance(actor_id, str) or not isinstance(password, str):
            fail("AUTH_FAILED")
        with self.store.connect() as conn:
            row = conn.execute("SELECT * FROM users WHERE actor_id=?",
                               (actor_id,)).fetchone()
        if row is None or not row["active"]:
            fail("AUTH_FAILED")
        if not hmac.compare_digest(password_digest(password, row["salt"]),
                                   row["password_hash"]):
            fail("AUTH_FAILED")
        token = secrets.token_hex(32)
        self._sessions[token] = actor_id
        return Principal(actor_id, row["role"], True, token)

    def require(self, principal, conn):
        if not isinstance(principal, Principal):
            fail("AUTH_FAILED")
        if self._sessions.get(principal.token) != principal.actor_id:
            fail("AUTH_FAILED")
        row = conn.execute("SELECT * FROM users WHERE actor_id=?",
                           (principal.actor_id,)).fetchone()
        if not row or not row["active"] or not principal.active:
            fail("AUTH_FAILED")
        if row["role"] != principal.role:
            fail("AUTH_FAILED")
        return principal
