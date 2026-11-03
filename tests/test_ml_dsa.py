"""ML-DSA（FIPS 204）后量子签名接入的安全测试。

覆盖：MLDSASigner 尺寸/能力、Base64 往返与篡改拒绝、参数集注册、
context 域分离、与 SM2 尺寸互斥、默认算法切换后的端到端审批、
旧 Hex SM2 在 ML-DSA 默认下的只读兼容、同一主体 SM2/ML-DSA 密钥共存。
"""
import sqlite3
import tempfile
import unittest
from pathlib import Path

from lab import config
from lab.crypto import Crypto
from lab.crypto_encoding import b64_to_bytes_strict, detect_encoding
from lab.errors import LabError
from lab.signers import MLDSASigner, SM2Signer, get_signer
from tasks.workflow_tasks import handle_approval
from tests.helpers import LabCase

HEX_PUBLIC = ("09f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020"
              "ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13")
HEX_SIGNATURE = ("f5a03b0648d2c4630eeac513e1bb81a15944da3827d5b74143ac7eaceee720b3"
                 "b1b6aa29df212fd8763182bc0d421ca1bb9038fd1f7f42d4840b69c485bbc1aa")


class MLDSASignerTests(unittest.TestCase):
    def test_ml_dsa_65_roundtrip_and_tamper(self):
        signer = get_signer("ML-DSA-65")
        self.assertIsInstance(signer, MLDSASigner)
        self.assertTrue(signer.quantum_resistant)
        private, public = signer.generate_keypair()
        self.assertEqual(len(b64_to_bytes_strict(public, 1952)), 1952)
        signature = signer.sign(private, b"post-quantum approval")
        self.assertEqual(len(b64_to_bytes_strict(signature, 3309)), 3309)
        self.assertTrue(signer.verify(public, b"post-quantum approval", signature))
        self.assertFalse(signer.verify(public, b"post-quantum approvaL", signature))
        self.assertTrue(signer.validate_public_key(public))

    def test_parameter_sets_are_registered_and_sized(self):
        for alg, pk, sk, sig in (("ML-DSA-44", 1312, 2560, 2420),
                                 ("ML-DSA-65", 1952, 4032, 3309),
                                 ("ML-DSA-87", 2592, 4896, 4627)):
            with self.subTest(alg=alg):
                signer = get_signer(alg)
                self.assertEqual(signer.alg_id, alg)
                self.assertEqual(signer.public_key_bytes, pk)
                self.assertEqual(signer.private_key_bytes, sk)
                self.assertEqual(signer.signature_bytes, sig)

    def test_ml_dsa_rejects_sm2_sized_material(self):
        signer = get_signer("ML-DSA-65")
        sm2_private, sm2_public = SM2Signer().generate_keypair()
        sm2_sig = SM2Signer().sign(sm2_private, b"x")
        # SM2 的 64 字节公钥/签名不是合法的 ML-DSA 输入。
        self.assertFalse(signer.validate_public_key(sm2_public))
        self.assertFalse(signer.verify(sm2_public, b"x", sm2_sig))

    def test_ml_dsa_context_domain_separation(self):
        signer = get_signer("ML-DSA-65")
        private, public = signer.generate_keypair()
        signature = signer.sign(private, b"m", context=b"aid-approval-v1")
        self.assertTrue(signer.verify(public, b"m", signature, context=b"aid-approval-v1"))
        self.assertFalse(signer.verify(public, b"m", signature, context=b"other"))
        self.assertFalse(signer.verify(public, b"m", signature))


class LegacyCompatUnderMLDSATests(unittest.TestCase):
    def test_hex_sm2_verifies_without_hint_even_when_default_is_ml_dsa(self):
        saved = config.SIGNING_ALGORITHM
        config.SIGNING_ALGORITHM = "ML-DSA-65"
        try:
            with tempfile.TemporaryDirectory() as directory:
                crypto = Crypto(Path(directory) / "private")
                # 无 alg/encoding 提示的验签走 SM2 只读兼容路径。
                self.assertTrue(crypto.verify(HEX_PUBLIC, b"message digest", HEX_SIGNATURE))
        finally:
            config.SIGNING_ALGORITHM = saved


class KeyCoexistenceTests(unittest.TestCase):
    def test_sm2_and_ml_dsa_keys_coexist_for_same_owner(self):
        saved = config.SIGNING_ALGORITHM
        try:
            with tempfile.TemporaryDirectory() as directory:
                private = Path(directory) / "private"
                private.mkdir()
                config.SIGNING_ALGORITHM = "SM2"
                crypto = Crypto(private)
                sm2_row = crypto.vault.initialize_signer("T017")
                self.assertEqual(sm2_row["key_id"], "T017-SM2-01")

                config.SIGNING_ALGORITHM = "ML-DSA-65"
                ml_row = crypto.vault.initialize_signer("T017")
                self.assertEqual(ml_row["key_id"], "T017-ML-DSA-65-01")
                self.assertEqual(ml_row["alg"], "ML-DSA-65")

                # 旧 SM2 密钥仍可签名并验签（旧数据只读兼容）。
                signature = crypto.sign("T017", "T017-SM2-01", b"legacy-data")
                self.assertTrue(crypto.verify(sm2_row["public_key"], b"legacy-data",
                                              signature, alg="SM2"))
        finally:
            config.SIGNING_ALGORITHM = saved

    def test_legacy_unique_schema_migrates_to_multikey(self):
        saved = config.SIGNING_ALGORITHM
        try:
            with tempfile.TemporaryDirectory() as directory:
                private = Path(directory) / "private"
                private.mkdir()
                connection = sqlite3.connect(str(private / "keys.sqlite3"))
                connection.executescript("""
                CREATE TABLE signing_keys(
                 key_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL UNIQUE,
                 private_key TEXT NOT NULL, public_key TEXT NOT NULL,
                 alg TEXT NOT NULL DEFAULT 'SM2');
                CREATE TABLE material_keys(
                 key_id TEXT PRIMARY KEY, key_hex TEXT NOT NULL, metadata TEXT NOT NULL);
                """)
                connection.commit()
                connection.close()

                crypto = Crypto(private)
                config.SIGNING_ALGORITHM = "SM2"
                crypto.vault.initialize_signer("T017")
                # 旧库的 owner_id UNIQUE 已被平滑迁移去掉，同一主体可再持 ML-DSA 密钥。
                config.SIGNING_ALGORITHM = "ML-DSA-65"
                crypto.vault.initialize_signer("T017")
                with crypto.vault.connection() as conn:
                    rows = [dict(r) for r in conn.execute(
                        "SELECT key_id, alg FROM signing_keys WHERE owner_id='T017'")]
                self.assertEqual({r["key_id"] for r in rows},
                                 {"T017-SM2-01", "T017-ML-DSA-65-01"})
        finally:
            config.SIGNING_ALGORITHM = saved


class MLDSAWorkflowTests(LabCase):
    @classmethod
    def setUpClass(cls):
        cls._saved_alg = config.SIGNING_ALGORITHM
        config.SIGNING_ALGORITHM = "ML-DSA-65"

    @classmethod
    def tearDownClass(cls):
        config.SIGNING_ALGORITHM = cls._saved_alg

    def test_ml_dsa_approval_end_to_end(self):
        self.submitted()
        manifest, signature = self.packet()
        self.assertEqual(manifest["signing_key_id"], "T017-ML-DSA-65-01")
        with self.ctx.store.connect() as conn:
            record = self.ctx.store.registry(conn)[manifest["signing_key_id"]]
        self.assertEqual(record["alg"], "ML-DSA-65")
        self.assertEqual(record["encoding"], "base64")
        self.assertEqual(detect_encoding(record["public_key"], 1952), "base64")

        approved = handle_approval(self.ctx, self.user("T017"), manifest, signature)
        self.assertEqual(approved["status"], "APPROVED")
        with self.ctx.store.connect() as conn:
            row = conn.execute("SELECT sig_alg, sig_encoding, signature"
                               " FROM approvals").fetchone()
        self.assertEqual(row["sig_alg"], "ML-DSA-65")
        self.assertEqual(row["sig_encoding"], "base64")
        self.assertEqual(detect_encoding(row["signature"], 3309), "base64")

    def test_ml_dsa_tampered_approval_rejected(self):
        self.submitted()
        manifest, signature = self.packet()
        manifest["decision"] = "reject"
        with self.assertRaises(LabError) as caught:
            handle_approval(self.ctx, self.user("T017"), manifest, signature)
        self.assertEqual(caught.exception.code, "SIGNATURE_INVALID")
