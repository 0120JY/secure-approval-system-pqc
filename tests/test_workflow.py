"""业务验收T01至T10及必要回归：检查真实状态、调用次数和审计。"""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from unittest.mock import patch
import base64
import json
import uuid
from lab.auth import Principal
from lab.errors import LabError
from tasks.document_tasks import build_approval_manifest, canonicalize_manifest
from tasks.workflow_tasks import submit_material, handle_approval, read_material
from tests.helpers import LabCase, APP, CONTENT


class WorkflowTests(LabCase):
    def test_T01_normal_submit_approve_read_and_audit(self):
        result = self.submitted()
        self.assertEqual(result["status"], "SUBMITTED")
        manifest, signature = self.packet()
        approved = handle_approval(self.ctx, self.user("T017"), manifest, signature)
        self.assertEqual(approved["status"], "APPROVED")
        self.assertEqual(self.ctx.store.count("approvals"), 1)
        self.assertEqual(read_material(self.ctx, self.user("F001"), APP, "Q1"), CONTENT)
        events = self.ctx.audit_events(self.user("A001"))
        self.assertTrue(any(e["request_id"] == "R103" and e["outcome"] == "SUCCESS" for e in events))

    def test_T02_tampered_approval_does_not_archive(self):
        self.submitted()
        manifest, signature = self.packet()
        manifest["decision"] = "reject"
        self.assert_code("SIGNATURE_INVALID", handle_approval,
                         self.ctx, self.user("T017"), manifest, signature)
        self.assertEqual(self.state()["status"], "SUBMITTED")
        self.assertEqual(self.ctx.store.count("approvals"), 0)
        self.assertEqual(self.events()[-1]["stage"], "signature")

    def test_T03_old_signature_is_not_valid_for_new_version(self):
        self.submitted()
        manifest, signature = self.packet()
        self.submitted(CONTENT+b"version 2")
        self.assert_code("VERSION_MISMATCH", handle_approval,
                         self.ctx, self.user("T017"), manifest, signature)
        self.assertEqual(self.state()["doc_version"], 2)
        self.assertEqual(self.state()["status"], "SUBMITTED")
        self.assertEqual(self.ctx.store.count("approvals"), 0)

    def test_T04_valid_signature_from_unassigned_counselor_is_denied(self):
        self.submitted()
        with self.ctx.store.connect() as conn:
            app = self.ctx.store.app(conn, APP)
            doc = self.ctx.store.document(conn, APP, 1)
        manifest = build_approval_manifest(app, doc, self.user("T018"), "approve", "R-WRONG", self.clock)
        signature = self.signed(manifest, "T018")
        before = self.ctx.crypto.calls["verify"]
        opened = self.ctx.crypto.calls["open"]
        self.assert_code("FORBIDDEN", handle_approval,
                         self.ctx, self.user("T018"), manifest, signature)
        self.assertEqual(self.ctx.crypto.calls["verify"], before+1)
        self.assertEqual(self.ctx.crypto.calls["open"], opened)
        self.assertEqual(self.ctx.store.count("approvals"), 0)

    def test_T05_other_student_and_auditor_never_trigger_decrypt(self):
        self.submitted()
        before = self.ctx.crypto.calls["open"]
        for actor in ["S002", "A001", "F001"]:
            with self.subTest(actor=actor):
                self.assert_code("FORBIDDEN", read_material,
                                 self.ctx, self.user(actor), APP, "Q-"+actor)
        self.assertEqual(before, self.ctx.crypto.calls["open"])
        self.assertGreater(len(self.ctx.audit_events(self.user("A001"))), 0)

    def test_T06_retry_has_one_effect_and_same_approval_id(self):
        self.submitted()
        manifest, signature = self.packet()
        first = handle_approval(self.ctx, self.user("T017"), manifest, signature)
        again = handle_approval(self.ctx, self.user("T017"), manifest, signature)
        self.assertFalse(first["replayed"])
        self.assertTrue(again["replayed"])
        self.assertEqual(first["approval_id"], again["approval_id"])
        self.assertEqual(self.ctx.store.count("approvals"), 1)
        self.assertEqual(self.events()[-1]["outcome"], "REPLAY")

    def test_T07_same_request_id_new_valid_signed_content_is_conflict(self):
        self.submitted()
        manifest, signature = self.packet()
        handle_approval(self.ctx, self.user("T017"), manifest, signature)
        altered = dict(manifest, decision="reject")
        altered_sig = self.signed(altered)
        self.assert_code("REQUEST_CONFLICT", handle_approval,
                         self.ctx, self.user("T017"), altered, altered_sig)
        self.assertEqual(self.state()["status"], "APPROVED")
        self.assertEqual(self.ctx.store.count("approvals"), 1)

    def test_T08_ciphertext_and_tag_tampering_rejected(self):
        self.submitted()
        with self.ctx.store.connect() as conn:
            original = self.ctx.store.document(conn, APP, 1)["envelope"]
        for field in ["ciphertext", "tag"]:
            with self.subTest(field=field):
                altered = dict(original)
                raw = bytearray(base64.b64decode(altered[field])); raw[0] ^= 1
                altered[field] = base64.b64encode(raw).decode("ascii")
                with self.ctx.store.transaction() as conn:
                    conn.execute("UPDATE documents SET envelope=? WHERE application_id=? AND version=1",
                                 (json.dumps(altered), APP))
                self.assert_code("INTEGRITY_ERROR", read_material,
                                 self.ctx, self.user("S001"), APP, "Q-TAMPER-"+field)
                self.assertEqual(self.events()[-1]["outcome"], "DENIED")

    def test_T09_encrypt_service_failure_leaves_no_document(self):
        self.ctx.crypto.faults.add("seal")
        self.assert_code("CRYPTO_UNAVAILABLE", self.submitted)
        self.assertEqual(self.state()["status"], "DRAFT")
        self.assertEqual(self.state()["doc_version"], 0)
        self.assertEqual(self.ctx.store.count("documents"), 0)
        self.assertEqual(self.ctx.store.count("processed_requests"), 0)
        self.assertEqual(self.events()[-1]["stage"], "encrypt")

    def test_T09_verify_service_failure_does_not_approve(self):
        self.submitted()
        manifest, signature = self.packet()
        self.ctx.crypto.faults.add("verify")
        self.assert_code("CRYPTO_UNAVAILABLE", handle_approval,
                         self.ctx, self.user("T017"), manifest, signature)
        self.assertEqual(self.ctx.store.count("approvals"), 0)
        self.assertEqual(self.state()["status"], "SUBMITTED")

    def test_T10_no_plaintext_or_key_values_in_server_storage(self):
        self.submitted()
        manifest, signature = self.packet()
        handle_approval(self.ctx, self.user("T017"), manifest, signature)
        read_material(self.ctx, self.user("F001"), APP, "Q-NO-PLAIN")
        server_bytes = b"".join(p.read_bytes() for p in (self.ctx.root/"server").rglob("*") if p.is_file())
        self.assertNotIn(CONTENT, server_bytes)
        self.assertNotIn(b"PRIVATE-MATERIAL-MARKER-7c9f4a21", server_bytes)
        with self.ctx.crypto.vault.connection() as conn:
            material_keys = [r[0] for r in conn.execute("SELECT key_hex FROM material_keys")]
            private_keys = [r[0] for r in conn.execute("SELECT private_key FROM signing_keys")]
        for key in material_keys + private_keys:
            self.assertNotIn(key.encode("ascii"), server_bytes)
            self.assertNotIn(bytes.fromhex(key), server_bytes)

    def test_retry_with_new_random_signature_still_has_one_effect(self):
        self.submitted()
        manifest, signature = self.packet()
        first = handle_approval(self.ctx, self.user("T017"), manifest, signature)
        second_sig = self.signed(manifest)
        self.assertNotEqual(signature, second_sig)
        repeated = handle_approval(self.ctx, self.user("T017"), manifest, second_sig)
        self.assertTrue(repeated["replayed"])
        self.assertEqual(first["approval_id"], repeated["approval_id"])
        self.assertEqual(self.ctx.store.count("approvals"), 1)

    def test_cached_retry_after_window_does_not_create_new_effect(self):
        self.submitted()
        manifest, signature = self.packet()
        first = handle_approval(self.ctx, self.user("T017"), manifest, signature)
        self.clock += 600
        repeated = handle_approval(self.ctx, self.user("T017"), manifest, signature)
        self.assertEqual(first["approval_id"], repeated["approval_id"])
        self.assertTrue(repeated["replayed"])

    def test_expired_first_request_is_denied(self):
        self.submitted()
        manifest, _ = self.packet()
        manifest["issued_at"] -= 301
        self.assert_code("REQUEST_EXPIRED", handle_approval, self.ctx, self.user("T017"),
                         manifest, self.signed(manifest))
        self.assertEqual(self.ctx.store.count("approvals"), 0)

    def test_future_first_request_is_denied(self):
        self.submitted()
        manifest, _ = self.packet()
        manifest["issued_at"] += 31
        self.assert_code("REQUEST_EXPIRED", handle_approval, self.ctx, self.user("T017"),
                         manifest, self.signed(manifest))
        self.assertEqual(self.state()["status"], "SUBMITTED")

    def test_different_request_ids_cannot_approve_same_version_twice(self):
        self.submitted()
        manifest, signature = self.packet()
        handle_approval(self.ctx, self.user("T017"), manifest, signature)
        another = dict(manifest, request_id="R104")
        self.assert_code("INVALID_STATE", handle_approval, self.ctx, self.user("T017"),
                         another, self.signed(another))
        self.assertEqual(self.ctx.store.count("approvals"), 1)

    def test_rejection_allows_new_version_and_new_approval(self):
        self.submitted()
        manifest, signature = self.packet(decision="reject")
        rejected = handle_approval(self.ctx, self.user("T017"), manifest, signature)
        self.assertEqual(rejected["status"], "REJECTED")
        self.assert_code("FORBIDDEN", read_material, self.ctx, self.user("F001"), APP, "Q-REJECTED")
        self.submitted(CONTENT+b"corrected")
        manifest2, signature2 = self.packet(request_id="R104")
        handle_approval(self.ctx, self.user("T017"), manifest2, signature2)
        self.assertEqual(self.state()["status"], "APPROVED")
        self.assertEqual(self.state()["doc_version"], 2)
        self.assertEqual(self.ctx.store.count("approvals"), 2)

    def test_upload_retry_does_not_increment_version(self):
        actor = self.user("S001")
        first = submit_material(self.ctx, actor, APP, CONTENT, "UP-SAME")
        repeat = submit_material(self.ctx, actor, APP, CONTENT, "UP-SAME")
        self.assertEqual(first["doc_version"], repeat["doc_version"])
        self.assertTrue(repeat["replayed"])
        self.assertEqual(self.ctx.crypto.calls["seal"], 1)

    def test_upload_id_conflict_does_not_replace_document(self):
        actor = self.user("S001")
        submit_material(self.ctx, actor, APP, CONTENT, "UP-SAME")
        self.assert_code("REQUEST_CONFLICT", submit_material,
                         self.ctx, actor, APP, CONTENT+b"different", "UP-SAME")
        self.assertEqual(self.state()["doc_version"], 1)

    def test_file_size_and_type_validation(self):
        for content in [b"", "not bytes", b"x"*(1024*1024+1)]:
            with self.subTest(kind=type(content).__name__):
                self.assert_code("INVALID_INPUT", submit_material,
                                 self.ctx, self.user("S001"), APP, content, "UP-SIZE")
        self.assertEqual(self.ctx.store.count("documents"), 0)

    def test_forged_principal_is_not_an_authenticated_session(self):
        self.submitted()
        before = self.ctx.crypto.calls["open"]
        forged = Principal("S001", "student")
        self.assert_code("AUTH_FAILED", read_material, self.ctx, forged, APP, "Q-FORGED")
        self.assertEqual(self.ctx.crypto.calls["open"], before)

    def test_current_account_and_key_revocation_are_checked_on_retry(self):
        self.submitted()
        manifest, signature = self.packet()
        handle_approval(self.ctx, self.user("T017"), manifest, signature)
        with self.ctx.store.transaction() as conn:
            conn.execute("UPDATE public_keys SET active=0 WHERE key_id='T017-SM2-01'")
        self.assert_code("UNTRUSTED_KEY", handle_approval,
                         self.ctx, self.user("T017"), manifest, signature)
        self.assertEqual(self.ctx.store.count("approvals"), 1)
        with self.ctx.store.transaction() as conn:
            conn.execute("UPDATE users SET active=0 WHERE actor_id='T017'")
        self.assert_code("AUTH_FAILED", handle_approval,
                         self.ctx, self.user("T017"), manifest, signature)

    def test_valid_signature_with_wrong_actual_digest_is_denied(self):
        self.submitted()
        manifest, _ = self.packet()
        altered = dict(manifest, file_sm3="0"*64)
        self.assert_code("DOCUMENT_MISMATCH", handle_approval, self.ctx, self.user("T017"),
                         altered, self.signed(altered))
        self.assertEqual(self.ctx.store.count("approvals"), 0)

    def test_read_crypto_failure_does_not_become_empty_success(self):
        self.submitted()
        self.ctx.crypto.faults.add("open")
        self.assert_code("CRYPTO_UNAVAILABLE", read_material,
                         self.ctx, self.user("S001"), APP, "Q-FAIL")
        self.assertEqual(self.events()[-1]["outcome"], "DENIED")

    def test_transaction_rollback_also_discards_new_material_key(self):
        with patch.object(self.ctx.store, "save_request", side_effect=LabError("CRYPTO_UNAVAILABLE")):
            self.assert_code("CRYPTO_UNAVAILABLE", self.submitted)
        self.assertEqual(self.ctx.store.count("documents"), 0)
        self.assertEqual(self.state()["doc_version"], 0)
        with self.ctx.crypto.vault.connection() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM material_keys").fetchone()[0], 0)
        self.assertEqual(self.events()[-1]["outcome"], "DENIED")

    def test_concurrent_identical_approvals_have_exactly_one_effect(self):
        self.submitted()
        manifest, signature = self.packet()
        principal = self.user("T017")
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda _: handle_approval(self.ctx, principal, manifest, signature),
                                    range(6)))
        self.assertEqual(sum(not r["replayed"] for r in results), 1)
        self.assertEqual(len({r["approval_id"] for r in results}), 1)
        self.assertEqual(self.ctx.store.count("approvals"), 1)

    def test_approval_mid_commit_failure_rolls_back_state_and_record(self):
        self.submitted()
        manifest, signature = self.packet()
        with patch.object(self.ctx.store, "save_request", side_effect=LabError("CRYPTO_UNAVAILABLE")):
            self.assert_code("CRYPTO_UNAVAILABLE", handle_approval,
                             self.ctx, self.user("T017"), manifest, signature)
        self.assertEqual(self.state()["status"], "SUBMITTED")
        self.assertEqual(self.ctx.store.count("approvals"), 0)
        self.assertEqual(self.ctx.store.count("processed_requests"), 1)  # 仅有先前的上传记录
        self.assertEqual(self.events()[-1]["outcome"], "DENIED")
