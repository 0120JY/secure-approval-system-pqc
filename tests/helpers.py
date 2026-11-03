from pathlib import Path
import tempfile
import unittest
import uuid
from lab.auth import DEMO_PASSWORD
from lab.context import Context
from lab.errors import LabError
from tasks.workflow_tasks import submit_material

APP = "APP-2026-001"
CONTENT = ("虚构奖助学金材料\nS001\nPRIVATE-MATERIAL-MARKER-7c9f4a21\n").encode("utf-8")


def sample_manifest():
    return {"schema": "aid-approval-v1", "application_id": APP, "student_id": "S001",
            "doc_version": 1, "file_sm3": "a"*64, "decision": "approve",
            "approver_id": "T017", "signing_key_id": "T017-SM2-01",
            "request_id": "R103", "issued_at": 1_800_000_000}


class LabCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aid_lab_test_")
        self.addCleanup(self.temp.cleanup)
        self.clock = 1_800_000_000
        self.ctx = Context(Path(self.temp.name), clock=lambda: self.clock)
        self._principals = {}

    def user(self, actor_id):
        if actor_id not in self._principals:
            self._principals[actor_id] = self.ctx.auth.login(actor_id, DEMO_PASSWORD)
        return self._principals[actor_id]

    def submitted(self, content=CONTENT):
        return submit_material(self.ctx, self.user("S001"), APP, content,
                               "UP-" + uuid.uuid4().hex)

    def state(self):
        with self.ctx.store.connect() as conn:
            return self.ctx.store.app(conn, APP)

    def packet(self, request_id="R103", decision="approve"):
        return self.ctx.prepare_approval(self.user("T017"), APP, decision, request_id)

    def signed(self, manifest, actor_id="T017"):
        from tasks.document_tasks import canonicalize_manifest
        return self.ctx.crypto.sign(actor_id, manifest["signing_key_id"],
                                    canonicalize_manifest(manifest))

    def assert_code(self, code, function, *args, **kwargs):
        with self.assertRaises(LabError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def events(self):
        with self.ctx.store.connect() as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM audit_events ORDER BY event_id")]
