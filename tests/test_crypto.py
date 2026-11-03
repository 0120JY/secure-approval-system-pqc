"""底层算法自检；与业务任务实现相互独立。"""
from pathlib import Path
import copy
import tempfile
import unittest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from lab.crypto import Crypto, sm3_hex, sm2_engine
from lab.errors import LabError


class CryptoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aid_crypto_")
        self.addCleanup(self.temp.cleanup)
        self.crypto = Crypto(Path(self.temp.name) / "private")
        self.meta = {"application_id": "APP-TEST", "student_id": "S001", "doc_version": 1}

    def test_sm3_known_answer(self):
        self.assertEqual(sm3_hex(b"abc"),
                         "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")

    def test_sm4_block_known_answer(self):
        value = bytes.fromhex("0123456789abcdeffedcba9876543210")
        enc = Cipher(algorithms.SM4(value), modes.ECB()).encryptor()
        self.assertEqual((enc.update(value)+enc.finalize()).hex(),
                         "681edf34d206965e86b3e94f536e4246")

    def test_sm4_gcm_rfc8998_vector(self):
        # RFC 8998 Appendix A.1，ECB仅用于上一个单分组已知答案测试。
        key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        nonce = bytes.fromhex("00001234567800000000abcd")
        aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        plain = bytes.fromhex("aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb"
                              "ccccccccccccccccdddddddddddddddd"
                              "eeeeeeeeeeeeeeeeffffffffffffffff"
                              "eeeeeeeeeeeeeeeeaaaaaaaaaaaaaaaa")
        enc = Cipher(algorithms.SM4(key), modes.GCM(nonce)).encryptor()
        enc.authenticate_additional_data(aad)
        ct = enc.update(plain) + enc.finalize()
        self.assertEqual(ct.hex(), "17f399f08c67d5ee19d0dc9969c4bb7d"
                         "5fd46fd3756489069157b282bb200735"
                         "d82710ca5c22f0ccfa7cbf93d496ac15"
                         "a56834cbcf98c397b4024a2691233b8d")
        self.assertEqual(enc.tag.hex(), "83de3541e4c2b58177e065a9bf7b62ec")

    def test_sm2_roundtrip_and_message_tamper(self):
        signer = self.crypto.vault.initialize_signer("T017")
        sig = self.crypto.sign("T017", signer["key_id"], b"approval-data")
        self.assertTrue(self.crypto.verify(signer["public_key"], b"approval-data", sig))
        self.assertFalse(self.crypto.verify(signer["public_key"], b"changed", sig))

    def test_sm2_known_public_key_and_signature(self):
        public = ("09f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020"
                  "ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13")
        signature = ("f5a03b0648d2c4630eeac513e1bb81a15944da3827d5b74143ac7eaceee720b3"
                     "b1b6aa29df212fd8763182bc0d421ca1bb9038fd1f7f42d4840b69c485bbc1aa")
        self.assertTrue(self.crypto.verify(public, b"message digest", signature))

    def test_sm2_malformed_and_zero_signature_rejected(self):
        signer = self.crypto.vault.initialize_signer("T017")
        for signature in ["0"*128, "not-a-signature", "ab", None]:
            with self.subTest(signature_type=type(signature).__name__):
                self.assertFalse(self.crypto.verify(signer["public_key"], b"data", signature))

    def test_public_key_leading_zero_is_preserved(self):
        # d=11对应的合法点恰好以04开头，覆盖3.2.2的坐标截短问题。
        public = ("04b3cb10c9c6d8e27c1aab770f67f543125dcdd589c2ff82668c74d78ce20ace63"
                  "516355287e39fe4918e5c02e2b0b930c94816e63c4bc72739a8fd805174a4b")
        self.assertEqual(sm2_engine(public_key=public).public_key, public)
        signature = sm2_engine(f"{11:064x}", public).sign_with_sm3(
            b"leading-coordinate-regression", random_hex_str="2"*64)
        self.assertTrue(self.crypto.verify(public, b"leading-coordinate-regression", signature))

    def test_gcm_roundtrip_and_new_key_per_encryption(self):
        first = self.crypto.seal("archive_service", b"material", self.meta)
        second = self.crypto.seal("archive_service", b"material", self.meta)
        self.assertNotEqual(first["key_id"], second["key_id"])
        self.assertNotEqual(first["nonce"], second["nonce"])
        self.assertEqual(self.crypto.open("query_service", first, self.meta), b"material")

    def test_gcm_modified_tag_rejected(self):
        envelope = self.crypto.seal("archive_service", b"sensitive", self.meta)
        envelope["tag"] = "AAAAAAAAAAAAAAAAAAAAAA=="
        with self.assertRaises(LabError) as caught:
            self.crypto.open("query_service", envelope, self.meta)
        self.assertEqual(caught.exception.code, "INTEGRITY_ERROR")

    def test_gcm_wrong_aad_rejected(self):
        envelope = self.crypto.seal("archive_service", b"sensitive", self.meta)
        altered = dict(self.meta, doc_version=2)
        with self.assertRaises(LabError) as caught:
            self.crypto.open("query_service", envelope, altered)
        self.assertEqual(caught.exception.code, "INTEGRITY_ERROR")

    def test_service_permission_separation(self):
        envelope = self.crypto.seal("archive_service", b"sensitive", self.meta)
        for service in ["archive_service", "audit_service"]:
            with self.subTest(service=service):
                with self.assertRaises(LabError) as caught:
                    self.crypto.open(service, envelope, self.meta)
                self.assertEqual(caught.exception.code, "SERVICE_FORBIDDEN")

    def test_signer_cannot_use_other_private_key(self):
        self.crypto.vault.initialize_signer("T017")
        with self.assertRaises(LabError) as caught:
            self.crypto.sign("T018", "T017-SM2-01", b"message")
        self.assertEqual(caught.exception.code, "IDENTITY_MISMATCH")
