"""密码敏捷性改造的安全回归测试。

覆盖：Base64 规范编码与非规范形式拒绝、Signer 接口与算法注册表、
算法标识绑定、旧 Hex 只读兼容、数据库平滑迁移。
"""
import base64
import sqlite3
import tempfile
import unittest
from pathlib import Path

from lab import config
from lab.crypto import Crypto
from lab.crypto_encoding import b64_to_bytes_strict, detect_encoding
from lab.encoding import MANIFEST_KEYS
from lab.errors import LabError
from lab.signers import SM2Signer, get_signer
from lab.store import Store
from tasks.workflow_tasks import handle_approval
from tests.helpers import LabCase

HEX_PUBLIC = ("09f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020"
              "ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13")
HEX_SIGNATURE = ("f5a03b0648d2c4630eeac513e1bb81a15944da3827d5b74143ac7eaceee720b3"
                 "b1b6aa29df212fd8763182bc0d421ca1bb9038fd1f7f42d4840b69c485bbc1aa")


class Base64EncodingTests(unittest.TestCase):
    def test_standard_alphabet_and_padding(self):
        _, public = SM2Signer().generate_keypair()
        self.assertEqual(len(public), 88)
        self.assertTrue(public.endswith("=="))
        raw = base64.b64decode(public.encode("ascii"), validate=True)
        self.assertEqual(base64.b64encode(raw).decode("ascii"), public)
        self.assertEqual(detect_encoding(public, 64), "base64")

    def test_non_canonical_and_malformed_base64_rejected(self):
        self.assertEqual(b64_to_bytes_strict("AA==", 1), b"\x00")
        for value in ("AB==", "AA=", "AA", " AA==", "AA==\n", "-_==", "AA==="):
            with self.subTest(value=value):
                self.assertIsNone(b64_to_bytes_strict(value, 1))

    def test_signature_is_base64_and_roundtrips(self):
        signer = SM2Signer()
        private, public = signer.generate_keypair()
        signature = signer.sign(private, b"crypto-agility")
        self.assertEqual(len(signature), 88)
        self.assertEqual(detect_encoding(signature, 64), "base64")
        self.assertTrue(signer.verify(public, b"crypto-agility", signature))
        self.assertFalse(signer.verify(public, b"crypto-agilitY", signature))


class SignerRegistryTests(unittest.TestCase):
    def test_unknown_algorithm_is_rejected(self):
        for alg in ("ML-DSA-99", "RSA", ""):
            with self.subTest(alg=alg):
                with self.assertRaises(LabError) as caught:
                    get_signer(alg)
                self.assertEqual(caught.exception.code, "UNSUPPORTED_ALGORITHM")

    def test_algorithm_is_not_inferred_from_value_length(self):
        # 128 字符 Hex 不能作为算法线索；显式传入未注册算法必须拒绝。
        with tempfile.TemporaryDirectory() as directory:
            crypto = Crypto(Path(directory) / "private")
            with self.assertRaises(LabError) as caught:
                crypto.verify(HEX_PUBLIC, b"message digest", HEX_SIGNATURE,
                              alg="ML-DSA-99")
            self.assertEqual(caught.exception.code, "UNSUPPORTED_ALGORITHM")

    def test_signer_accepts_only_base64(self):
        signer = SM2Signer()
        _, public = signer.generate_keypair()
        self.assertFalse(signer.verify(public, b"message digest", HEX_SIGNATURE))
        self.assertFalse(signer.validate_public_key(HEX_PUBLIC))


class LegacyCompatibilityTests(unittest.TestCase):
    def test_legacy_hex_is_read_only_compatible(self):
        with tempfile.TemporaryDirectory() as directory:
            crypto = Crypto(Path(directory) / "private")
            self.assertTrue(crypto.verify(HEX_PUBLIC, b"message digest", HEX_SIGNATURE))
            self.assertTrue(crypto.verify(HEX_PUBLIC, b"message digest", HEX_SIGNATURE,
                                          encoding="hex"))
            self.assertFalse(crypto.verify(HEX_PUBLIC, b"changed", HEX_SIGNATURE))

    def test_old_database_schema_is_migrated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "server" / "business.sqlite3"
            database.parent.mkdir(parents=True)
            connection = sqlite3.connect(str(database))
            connection.executescript("""
            CREATE TABLE public_keys(
             key_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL,
             public_key TEXT NOT NULL, active INTEGER NOT NULL);
            CREATE TABLE approvals(
             approval_id TEXT PRIMARY KEY, application_id TEXT NOT NULL,
             doc_version INTEGER NOT NULL, actor_id TEXT NOT NULL,
             decision TEXT NOT NULL, manifest TEXT NOT NULL, signature TEXT NOT NULL,
             UNIQUE(application_id, doc_version));
            """)
            connection.commit()
            connection.close()

            store = Store(database)
            with store.connect() as conn:
                public_columns = {row["name"] for row in
                                  conn.execute("PRAGMA table_info(public_keys)")}
                approval_columns = {row["name"] for row in
                                    conn.execute("PRAGMA table_info(approvals)")}
            self.assertTrue({"alg", "encoding"} <= public_columns)
            self.assertTrue({"sig_alg", "sig_encoding"} <= approval_columns)

            with store.transaction() as conn:
                conn.execute("INSERT INTO public_keys(key_id, owner_id, public_key, active)"
                             " VALUES(?,?,?,?)", ("T017-SM2-01", "T017", HEX_PUBLIC, 1))
            with store.connect() as conn:
                record = store.registry(conn)["T017-SM2-01"]
            self.assertEqual(record["encoding"], "hex")
            crypto = Crypto(root / "private")
            self.assertTrue(crypto.verify(record["public_key"], b"message digest",
                                          HEX_SIGNATURE, alg=record["alg"],
                                          encoding=record["encoding"]))

    def test_old_vault_schema_gains_algorithm_column(self):
        # 该用例断言 SM2 世界行为；显式钉住算法，与系统默认（ML-DSA）无关。
        saved = config.SIGNING_ALGORITHM
        config.SIGNING_ALGORITHM = "SM2"
        try:
            with tempfile.TemporaryDirectory() as directory:
                private = Path(directory) / "private"
                private.mkdir()
                connection = sqlite3.connect(str(private / "keys.sqlite3"))
                connection.executescript("""
                CREATE TABLE signing_keys(
                 key_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL UNIQUE,
                 private_key TEXT NOT NULL, public_key TEXT NOT NULL);
                CREATE TABLE material_keys(
                 key_id TEXT PRIMARY KEY, key_hex TEXT NOT NULL, metadata TEXT NOT NULL);
                """)
                connection.commit()
                connection.close()

                crypto = Crypto(private)
                row = crypto.vault.initialize_signer("T017")
                self.assertEqual(row["alg"], "SM2")
                self.assertEqual(row["encoding"], "base64")
                with crypto.vault.connection() as conn:
                    columns = {item["name"] for item in
                               conn.execute("PRAGMA table_info(signing_keys)")}
                self.assertIn("alg", columns)
        finally:
            config.SIGNING_ALGORITHM = saved


class ConfigTests(unittest.TestCase):
    def test_key_id_template_is_algorithm_driven(self):
        # 模板仍是 {actor_id}-{algorithm}-01，算法经显式参数注入；
        # 系统默认已切换为 ML-DSA-65，但测试入口把历史套件钉在 SM2 上。
        self.assertEqual(config.key_id_for("T017", "SM2"), "T017-SM2-01")
        self.assertEqual(config.key_id_for("T017", "ML-DSA-65"), "T017-ML-DSA-65-01")


class BusinessIntegrationTests(LabCase):
    @classmethod
    def setUpClass(cls):
        # 这些断言以 SM2 世界为基准；显式钉住，与系统默认（ML-DSA）无关。
        cls._saved_alg = config.SIGNING_ALGORITHM
        config.SIGNING_ALGORITHM = "SM2"

    @classmethod
    def tearDownClass(cls):
        config.SIGNING_ALGORITHM = cls._saved_alg

    def test_new_public_key_registered_with_algorithm_and_base64(self):
        with self.ctx.store.connect() as conn:
            record = self.ctx.store.registry(conn)["T017-SM2-01"]
        self.assertEqual(record["alg"], "SM2")
        self.assertEqual(record["encoding"], "base64")
        self.assertEqual(detect_encoding(record["public_key"], 64), "base64")

    def test_new_approval_records_algorithm_and_base64(self):
        self.submitted()
        manifest, signature = self.packet()
        handle_approval(self.ctx, self.user("T017"), manifest, signature)
        with self.ctx.store.connect() as conn:
            row = conn.execute("SELECT sig_alg, sig_encoding, signature"
                               " FROM approvals").fetchone()
        self.assertEqual(row["sig_alg"], "SM2")
        self.assertEqual(row["sig_encoding"], "base64")
        self.assertEqual(detect_encoding(row["signature"], 64), "base64")

    def test_manifest_binds_algorithm_through_key_id(self):
        self.submitted()
        manifest, _ = self.packet()
        self.assertNotIn("sig_alg", MANIFEST_KEYS)
        self.assertEqual(manifest["signing_key_id"], "T017-SM2-01")
        with self.ctx.store.connect() as conn:
            record = self.ctx.store.registry(conn)[manifest["signing_key_id"]]
        self.assertEqual(record["alg"], "SM2")
