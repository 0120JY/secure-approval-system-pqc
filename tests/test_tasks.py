import copy
import json
import unittest
from dataclasses import replace
from lab.auth import Principal
from lab.encoding import strict_json_loads
from lab.errors import LabError
from tasks.document_tasks import (calculate_file_sm3, canonicalize_manifest,
                                  build_approval_manifest, check_document_binding)
from tasks.access_tasks import (authorize_action, validate_request_freshness,
                                verify_approval_signature)
from tests.helpers import LabCase, sample_manifest, APP, CONTENT


class DocumentContractTests(unittest.TestCase):
    def assert_code(self, code, fn, *args):
        with self.assertRaises(LabError) as caught:
            fn(*args)
        self.assertEqual(caught.exception.code, code)

    def test_task01_exact_bytes_and_type(self):
        self.assertEqual(calculate_file_sm3(b"abc"),
                         "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")
        self.assertNotEqual(calculate_file_sm3(b"abc"), calculate_file_sm3(b"abc\n"))
        self.assert_code("INVALID_INPUT", calculate_file_sm3, "abc")

    def test_task02_field_order_does_not_change_signed_bytes(self):
        manifest = sample_manifest()
        before = copy.deepcopy(manifest)
        reverse = dict(reversed(list(manifest.items())))
        expected = json.dumps(manifest, sort_keys=True, ensure_ascii=False,
                              separators=(",", ":")).encode("utf-8")
        self.assertEqual(canonicalize_manifest(reverse), expected)
        self.assertEqual(manifest, before)

    def test_task02_missing_extra_bool_and_bad_digest_rejected(self):
        bad = []
        m = sample_manifest(); del m["request_id"]; bad.append(m)
        bad.extend([dict(sample_manifest(), public_key="untrusted"),
                    dict(sample_manifest(), doc_version=True),
                    dict(sample_manifest(), issued_at=False),
                    dict(sample_manifest(), file_sm3="A"*64),
                    dict(sample_manifest(), decision="anything"),
                    dict(sample_manifest(), schema="different-protocol"),
                    dict(sample_manifest(), doc_version=1.0)])
        for manifest in bad:
            with self.subTest(changed=manifest):
                self.assert_code("INVALID_INPUT", canonicalize_manifest, manifest)

    def test_strict_json_rejects_duplicate_fields_and_nan(self):
        for raw in ['{"decision":"approve","decision":"reject"}', '{"x":NaN}']:
            with self.subTest(raw=raw):
                self.assert_code("INVALID_INPUT", strict_json_loads, raw)

    def test_task07_time_window_includes_boundaries(self):
        for timestamp in [700, 1000, 1030]:
            validate_request_freshness({"issued_at": timestamp}, 1000)
        for timestamp in [699, 1031]:
            self.assert_code("REQUEST_EXPIRED", validate_request_freshness,
                             {"issued_at": timestamp}, 1000)
        self.assert_code("INVALID_INPUT", validate_request_freshness,
                         {"issued_at": True}, 1000)


class PermissionTests(unittest.TestCase):
    def setUp(self):
        self.app = {"student_id": "S001", "assigned_approver": "T017",
                    "status": "SUBMITTED", "doc_version": 1}

    def test_task05_owner_and_assigned_counselor(self):
        authorize_action(Principal("S001", "student"), self.app, "submit")
        authorize_action(Principal("S001", "student"), self.app, "read")
        authorize_action(Principal("T017", "counselor"), self.app, "approve")

    def test_task05_resource_denials(self):
        for actor, role, action in [("S002", "student", "read"),
                                     ("T018", "counselor", "approve"),
                                     ("A001", "auditor", "read"),
                                     ("F001", "finance", "read")]:
            with self.subTest(actor=actor, action=action):
                with self.assertRaises(LabError) as caught:
                    authorize_action(Principal(actor, role), self.app, action)
                self.assertEqual(caught.exception.code, "FORBIDDEN")

    def test_task05_state_and_audit_permissions(self):
        approved = dict(self.app, status="APPROVED")
        authorize_action(Principal("F001", "finance"), approved, "read")
        authorize_action(Principal("A001", "auditor"), {}, "audit")
        for actor, role, action in [("S001", "student", "submit"),
                                     ("T017", "counselor", "approve")]:
            with self.assertRaises(LabError) as caught:
                authorize_action(Principal(actor, role), approved, action)
            self.assertEqual(caught.exception.code, "INVALID_STATE")
        with self.assertRaises(LabError):
            authorize_action(Principal("T017", "counselor", False), self.app, "approve")


class BindingAndTrustTests(LabCase):
    def test_task03_manifest_uses_current_subject_and_version(self):
        self.submitted()
        with self.ctx.store.connect() as conn:
            app = self.ctx.store.app(conn, APP)
            document = self.ctx.store.document(conn, APP, 1)
        manifest = build_approval_manifest(app, document, self.user("T017"),
                                           "approve", "R103", self.clock)
        self.assertEqual(manifest["student_id"], "S001")
        self.assertEqual(manifest["approver_id"], "T017")
        self.assertEqual(manifest["signing_key_id"], "T017-SM2-01")
        self.assertEqual(manifest["file_sm3"], calculate_file_sm3(CONTENT))
        self.assert_code("VERSION_MISMATCH", build_approval_manifest,
                         dict(app, doc_version=2), document, self.user("T017"),
                         "approve", "R103", self.clock)

    def test_task04_recomputes_actual_file_digest(self):
        self.submitted()
        manifest, _ = self.packet()
        with self.ctx.store.connect() as conn:
            app = self.ctx.store.app(conn, APP)
            document = self.ctx.store.document(conn, APP, 1)
        check_document_binding(manifest, app, document, CONTENT)
        self.assert_code("DOCUMENT_MISMATCH", check_document_binding,
                         manifest, app, document, CONTENT+b"changed")

    def test_task06_trusted_key_and_login_subject(self):
        self.submitted()
        manifest, signature = self.packet()
        with self.ctx.store.connect() as conn:
            registry = self.ctx.store.registry(conn)
        verify_approval_signature(manifest, signature, self.user("T017"), registry, self.ctx.crypto)
        self.assert_code("IDENTITY_MISMATCH", verify_approval_signature,
                         manifest, signature, self.user("T018"), registry, self.ctx.crypto)
        revoked = copy.deepcopy(registry); revoked["T017-SM2-01"]["active"] = 0
        self.assert_code("UNTRUSTED_KEY", verify_approval_signature,
                         manifest, signature, self.user("T017"), revoked, self.ctx.crypto)
