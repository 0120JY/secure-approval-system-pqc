"""SQLite数据访问与事务工具；业务判断由tasks完成。"""
from contextlib import contextmanager
from pathlib import Path
import json
import sqlite3
from . import config
from .encoding import json_text
from .errors import fail

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
 actor_id TEXT PRIMARY KEY, role TEXT NOT NULL, active INTEGER NOT NULL,
 salt TEXT NOT NULL, password_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS applications (
 application_id TEXT PRIMARY KEY, student_id TEXT NOT NULL,
 assigned_approver TEXT NOT NULL, status TEXT NOT NULL,
 doc_version INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS public_keys (
 key_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL,
 public_key TEXT NOT NULL, active INTEGER NOT NULL,
 alg TEXT NOT NULL DEFAULT 'SM2',
 encoding TEXT NOT NULL DEFAULT 'hex');
CREATE TABLE IF NOT EXISTS documents (
 application_id TEXT NOT NULL, version INTEGER NOT NULL,
 file_sm3 TEXT NOT NULL, key_id TEXT NOT NULL, envelope TEXT NOT NULL,
 PRIMARY KEY(application_id, version),
 FOREIGN KEY(application_id) REFERENCES applications(application_id));
CREATE TABLE IF NOT EXISTS approvals (
 approval_id TEXT PRIMARY KEY, application_id TEXT NOT NULL,
 doc_version INTEGER NOT NULL, actor_id TEXT NOT NULL,
 decision TEXT NOT NULL, manifest TEXT NOT NULL, signature TEXT NOT NULL,
 sig_alg TEXT NOT NULL DEFAULT 'SM2',
 sig_encoding TEXT NOT NULL DEFAULT 'hex',
 UNIQUE(application_id, doc_version));
CREATE TABLE IF NOT EXISTS processed_requests (
 actor_id TEXT NOT NULL, request_id TEXT NOT NULL, action TEXT NOT NULL,
 fingerprint TEXT NOT NULL, result TEXT NOT NULL,
 PRIMARY KEY(actor_id, request_id));
CREATE TABLE IF NOT EXISTS audit_events (
 event_id INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at INTEGER NOT NULL,
 actor_id TEXT NOT NULL, application_id TEXT NOT NULL, request_id TEXT NOT NULL,
 operation TEXT NOT NULL, stage TEXT NOT NULL, outcome TEXT NOT NULL,
 error_code TEXT NOT NULL);
"""


class Store:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.executescript(SCHEMA)
            self._migrate(conn)

    @staticmethod
    def _migrate(conn):
        """平滑迁移：为历史库补充算法与编码列，旧行沿用默认值（Hex）。"""
        columns = {
            "public_keys": {"alg": "TEXT NOT NULL DEFAULT 'SM2'",
                            "encoding": "TEXT NOT NULL DEFAULT 'hex'"},
            "approvals": {"sig_alg": "TEXT NOT NULL DEFAULT 'SM2'",
                          "sig_encoding": "TEXT NOT NULL DEFAULT 'hex'"},
        }
        for table, wanted in columns.items():
            existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
            for name, ddl in wanted.items():
                if name not in existing:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")

    def _connect(self):
        conn = sqlite3.connect(str(self.path), timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=15000")
        return conn

    @contextmanager
    def connect(self):
        conn = self._connect()
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    @contextmanager
    def transaction(self):
        """SQLite写事务串行化，去重检查和状态更新共用此连接。"""
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def app(self, conn, application_id):
        row = conn.execute("SELECT * FROM applications WHERE application_id=?",
                           (application_id,)).fetchone()
        if row is None:
            fail("NOT_FOUND")
        return dict(row)

    def document(self, conn, application_id, version):
        row = conn.execute(
            "SELECT * FROM documents WHERE application_id=? AND version=?",
            (application_id, version)).fetchone()
        if row is None:
            fail("NO_DOCUMENT")
        value = dict(row)
        value["envelope"] = json.loads(value["envelope"])
        return value

    def request(self, conn, actor_id, request_id):
        row = conn.execute(
            "SELECT * FROM processed_requests WHERE actor_id=? AND request_id=?",
            (actor_id, request_id)).fetchone()
        if row is None:
            return None
        value = dict(row)
        value["result"] = json.loads(value["result"])
        return value

    def save_request(self, conn, actor_id, request_id, action, fingerprint, result):
        conn.execute("INSERT INTO processed_requests VALUES(?,?,?,?,?)",
                     (actor_id, request_id, action, fingerprint, json_text(result)))

    def registry(self, conn):
        return {r["key_id"]: dict(r) for r in
                conn.execute("SELECT * FROM public_keys").fetchall()}

    def add_document(self, conn, application_id, version, digest, envelope):
        conn.execute("INSERT INTO documents VALUES(?,?,?,?,?)",
                     (application_id, version, digest, envelope["key_id"],
                      json_text(envelope)))
        conn.execute("UPDATE applications SET doc_version=?, status='SUBMITTED' "
                     "WHERE application_id=?", (version, application_id))

    def add_approval(self, conn, manifest, signature, approval_id):
        row = conn.execute("SELECT alg FROM public_keys WHERE key_id=?",
                           (manifest["signing_key_id"],)).fetchone()
        sig_alg = row["alg"] if row else config.SIGNING_ALGORITHM
        sig_encoding = config.WRITE_ENCODING
        conn.execute("INSERT INTO approvals VALUES(?,?,?,?,?,?,?,?,?)", (
            approval_id, manifest["application_id"], manifest["doc_version"],
            manifest["approver_id"], manifest["decision"],
            json_text(manifest), signature, sig_alg, sig_encoding))
        state = "APPROVED" if manifest["decision"] == "approve" else "REJECTED"
        conn.execute("UPDATE applications SET status=? WHERE application_id=?",
                     (state, manifest["application_id"]))

    def count(self, table):
        if table not in {"documents", "approvals", "processed_requests", "audit_events"}:
            raise ValueError("unsupported table")
        with self.connect() as conn:
            return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
