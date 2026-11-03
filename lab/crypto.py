"""国密与后量子算法适配器。

SM2: gmssl 3.2.2，固定ID 1234567812345678，底层签名编码为r||s十六进制，
对外统一以 Base64 承载公钥与签名（兼容历史 Hex 只读）。
SM3 / SM4-GCM: cryptography 46.0.3。所有随机数由secrets生成。
软件密钥库仅为本机参考实现边界，不具备硬件隔离或正式CA能力。
"""
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
import base64
import json
import secrets
import sqlite3
import threading
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from . import config
from .crypto_encoding import detect_encoding
from .encoding import json_text
from .errors import fail
# 历史兼容：SM2 底层原语迁至 signers，仍从这里 re-export。
from .signers import sm2_engine, new_sm2_keypair, valid_public_key, get_signer


def sm3_hex(data: bytes) -> str:
    if not isinstance(data, bytes):
        fail("INVALID_INPUT")
    digest = hashes.Hash(hashes.SM3())
    digest.update(data)
    return digest.finalize().hex()


class Vault:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / "keys.sqlite3"
        with self.connection() as conn:
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS signing_keys(
              key_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL,
              private_key TEXT NOT NULL, public_key TEXT NOT NULL,
              alg TEXT NOT NULL DEFAULT 'SM2');
            CREATE INDEX IF NOT EXISTS signing_keys_owner_idx ON signing_keys(owner_id);
            CREATE TABLE IF NOT EXISTS material_keys(
              key_id TEXT PRIMARY KEY, key_hex TEXT NOT NULL,
              metadata TEXT NOT NULL);
            """)
            self._migrate(conn)
        try:
            self.directory.chmod(0o700)
            self.path.chmod(0o600)
        except OSError:
            pass

    @staticmethod
    def _migrate(conn):
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(signing_keys)")}
        if "alg" not in cols:
            conn.execute("ALTER TABLE signing_keys ADD COLUMN alg TEXT NOT NULL DEFAULT 'SM2'")
        # 去掉 owner_id 的隐式 UNIQUE，允许同一主体同时持有 SM2 与 ML-DSA 密钥。
        auto_unique = [r for r in conn.execute("PRAGMA index_list(signing_keys)")
                       if r["origin"] == "u"]
        if auto_unique:
            conn.execute("""
            CREATE TABLE signing_keys_new(
              key_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL,
              private_key TEXT NOT NULL, public_key TEXT NOT NULL,
              alg TEXT NOT NULL DEFAULT 'SM2');
            """)
            conn.execute("INSERT INTO signing_keys_new"
                         "(key_id, owner_id, private_key, public_key, alg)"
                         " SELECT key_id, owner_id, private_key, public_key, alg"
                         " FROM signing_keys")
            conn.execute("DROP TABLE signing_keys")
            conn.execute("ALTER TABLE signing_keys_new RENAME TO signing_keys")
            conn.execute("CREATE INDEX signing_keys_owner_idx ON signing_keys(owner_id)")

    @contextmanager
    def connection(self):
        conn = sqlite3.connect(str(self.path), timeout=15)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def initialize_signer(self, owner_id):
        signer = get_signer(config.SIGNING_ALGORITHM)
        key_id = config.key_id_for(owner_id)
        with self.connection() as conn:
            row = conn.execute("SELECT * FROM signing_keys WHERE key_id=?",
                               (key_id,)).fetchone()
            if row is None:
                private_key, public_key = signer.generate_keypair()
                conn.execute("INSERT INTO signing_keys VALUES(?,?,?,?,?)",
                             (key_id, owner_id, private_key, public_key, signer.alg_id))
                alg, encoding = signer.alg_id, config.WRITE_ENCODING
            else:
                private_key = row["private_key"]
                public_key = row["public_key"]
                alg = row["alg"]
                encoding = detect_encoding(public_key, signer.public_key_bytes) or config.WRITE_ENCODING
        return {"key_id": key_id, "owner_id": owner_id,
                "public_key": public_key, "active": 1, "alg": alg, "encoding": encoding}

    def signing_key(self, key_id, actor_id):
        with self.connection() as conn:
            row = conn.execute("SELECT * FROM signing_keys WHERE key_id=?",
                               (key_id,)).fetchone()
        if not row or row["owner_id"] != actor_id:
            fail("IDENTITY_MISMATCH")
        return dict(row)


class Crypto:
    def __init__(self, private_directory):
        self.vault = Vault(private_directory)
        self.calls = Counter()
        self.faults = set()
        self._counter_lock = threading.Lock()

    def _operation(self, operation):
        with self._counter_lock:
            self.calls[operation] += 1
        if operation in self.faults:
            fail("CRYPTO_UNAVAILABLE")

    def sign(self, actor_id, key_id, data):
        self._operation("sign")
        row = self.vault.signing_key(key_id, actor_id)
        signer = get_signer(row.get("alg") or config.SIGNING_ALGORITHM)
        return signer.sign(row["private_key"], data)

    def verify(self, public_key, data, signature, alg=None, encoding=None):
        self._operation("verify")
        # 无算法提示的验签走 SM2 只读兼容路径，与新数据默认 ML-DSA 无关；
        # 编码与长度校验由具体 Signer 声明并内聚。
        signer = get_signer(alg or config.LEGACY_VERIFY_ALGORITHM)
        public_key = signer.normalize_public_key(public_key, encoding)
        signature = signer.normalize_signature(signature, encoding)
        if public_key is None or signature is None:
            return False
        return signer.verify(public_key, data, signature)

    def seal(self, service_id, plaintext, metadata):
        if service_id != "archive_service":
            fail("SERVICE_FORBIDDEN")
        self._operation("seal")
        key_id = "MAT-" + secrets.token_hex(16)
        key, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
        aad_data = {"schema": "aid-envelope-v1", "alg": "SM4-GCM",
                    "key_id": key_id, **metadata}
        encryptor = Cipher(algorithms.SM4(key), modes.GCM(nonce)).encryptor()
        encryptor.authenticate_additional_data(json_text(aad_data).encode("utf-8"))
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        with self.vault.connection() as conn:
            conn.execute("INSERT INTO material_keys VALUES(?,?,?)",
                         (key_id, key.hex(), json_text(metadata)))
        encode = lambda b: base64.b64encode(b).decode("ascii")
        return {"schema": "aid-envelope-v1", "alg": "SM4-GCM", "key_id": key_id,
                "nonce": encode(nonce), "ciphertext": encode(ciphertext),
                "tag": encode(encryptor.tag)}

    def open(self, service_id, envelope, expected_metadata):
        if service_id not in {"review_service", "query_service"}:
            fail("SERVICE_FORBIDDEN")
        self._operation("open")
        fields = {"schema", "alg", "key_id", "nonce", "ciphertext", "tag"}
        if not isinstance(envelope, dict) or set(envelope) != fields:
            fail("INTEGRITY_ERROR")
        if envelope["schema"] != "aid-envelope-v1" or envelope["alg"] != "SM4-GCM":
            fail("INTEGRITY_ERROR")
        if not all(isinstance(envelope[k], str) for k in fields):
            fail("INTEGRITY_ERROR")
        with self.vault.connection() as conn:
            row = conn.execute("SELECT * FROM material_keys WHERE key_id=?",
                               (envelope["key_id"],)).fetchone()
        if row is None:
            fail("KEY_NOT_FOUND")
        if json.loads(row["metadata"]) != expected_metadata:
            fail("INTEGRITY_ERROR")
        try:
            decode = lambda value: base64.b64decode(value.encode("ascii"), validate=True)
            nonce, ciphertext, tag = (decode(envelope[k]) for k in
                                       ("nonce", "ciphertext", "tag"))
            if len(nonce) != 12 or len(tag) != 16 or len(ciphertext) > 1024*1024:
                fail("INTEGRITY_ERROR")
            aad_data = {"schema": "aid-envelope-v1", "alg": "SM4-GCM",
                        "key_id": envelope["key_id"], **expected_metadata}
            decryptor = Cipher(algorithms.SM4(bytes.fromhex(row["key_hex"])),
                               modes.GCM(nonce, tag)).decryptor()
            decryptor.authenticate_additional_data(json_text(aad_data).encode("utf-8"))
            # update的临时结果只保存在函数内部；标签验证成功前不交付调用方。
            buffered = decryptor.update(ciphertext)
            tail = decryptor.finalize()
            return buffered + tail
        except (InvalidTag, ValueError, TypeError, UnicodeError):
            fail("INTEGRITY_ERROR")

    def discard_material_key(self, key_id):
        with self.vault.connection() as conn:
            conn.execute("DELETE FROM material_keys WHERE key_id=?", (key_id,))
