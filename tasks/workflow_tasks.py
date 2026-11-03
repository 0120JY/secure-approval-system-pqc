"""提交、审批与受控读取的事务编排。"""
import uuid
from lab.crypto import sm3_hex
from lab.encoding import json_text, valid_id
from lab.errors import LabError, fail
from .document_tasks import calculate_file_sm3, canonicalize_manifest, check_document_binding
from .access_tasks import authorize_action, verify_approval_signature, validate_request_freshness

MAX_MATERIAL_BYTES = 1024 * 1024


def submit_material(ctx, principal, application_id, content, request_id):
    """提交或更新本人的附件，并在加密成功后保存。

    校验ID、bytes类型及1..1048576字节大小。用ctx.store.transaction()
    的同一conn完成主体复核、资源授权、去重、持久化与成功审计。
    fingerprint为SM3(json_text({'action':'submit','application_id':ID,
    'file_sm3':摘要}).encode('utf-8'))。去重键是主体加request_id。
    已有同action同fingerprint请求返回原结果并replayed=True，写REPLAY审计；
    冲突抛REQUEST_CONFLICT。首次请求还要通过submit授权。
    新版本=current+1，调用crypto.seal('archive_service',content,
    ctx.metadata(application,version))后调用store.add_document。
    返回application_id/doc_version/status/file_sm3/replayed五个字段。
    请求记录action='submit'。审计operation='submit'，stage='commit'。
    LabError在事务外调用record_failure后重抛；保存失败时清除本次生成的
    材料密钥。不把原文写入业务库、临时文件或日志。
    """
    envelope = None
    stage = "input"
    try:
        if not valid_id(application_id) or not valid_id(request_id):
            fail("INVALID_INPUT")
        if not isinstance(content, bytes) or not (1 <= len(content) <= MAX_MATERIAL_BYTES):
            fail("INVALID_INPUT")
        digest = calculate_file_sm3(content)
        fingerprint = sm3_hex(json_text({
            "action": "submit",
            "application_id": application_id,
            "file_sm3": digest,
        }).encode("utf-8"))

        with ctx.store.transaction() as conn:
            stage = "authorization"
            ctx.require_principal(principal, conn)
            application = ctx.store.app(conn, application_id)

            stage = "idempotency"
            prior = ctx.store.request(conn, principal.actor_id, request_id)
            if prior is not None:
                if prior["action"] != "submit" or prior["fingerprint"] != fingerprint:
                    fail("REQUEST_CONFLICT")
                ctx.audit(conn, principal.actor_id, application_id, request_id,
                          "submit", "idempotency", "REPLAY")
                return dict(prior["result"], replayed=True)

            stage = "authorization"
            authorize_action(principal, application, "submit")

            version = application["doc_version"] + 1
            stage = "encrypt"
            envelope = ctx.crypto.seal("archive_service", content,
                                       ctx.metadata(application, version))

            stage = "commit"
            ctx.store.add_document(conn, application_id, version, digest, envelope)
            result = {
                "application_id": application_id,
                "doc_version": version,
                "status": "SUBMITTED",
                "file_sm3": digest,
                "replayed": False,
            }
            ctx.store.save_request(conn, principal.actor_id, request_id,
                                   "submit", fingerprint, result)
            ctx.audit(conn, principal.actor_id, application_id, request_id,
                      "submit", "commit", "SUCCESS")
            return result
    except LabError as error:
        # 事务已经回滚并关闭；本次未提交的材料密钥必须清除。
        if envelope is not None:
            ctx.crypto.discard_material_key(envelope["key_id"])
        ctx.record_failure(principal, application_id, request_id,
                           "submit", stage, error)
        raise
    except BaseException:
        # 非业务异常（如磁盘/驱动错误）同样不能遗留本次生成的材料密钥。
        if envelope is not None:
            ctx.crypto.discard_material_key(envelope["key_id"])
        raise


def handle_approval(ctx, principal, manifest, signature):
    """验证审批并原子提交，合法重试返回原结果。

    在 ctx.store.transaction 的 conn 内复核会话，规范化清单，加载可信登记表，
    调用 verify_approval_signature 验签，然后检查 access 授权。
    fingerprint=SM3(规范化清单)。
    先查主体加request_id的去重记录：同approve同fingerprint返回旧结果并
    replayed=True，写REPLAY；不同action/内容抛REQUEST_CONFLICT。
    首次处理才检查approve授权、当前材料绑定、时效。用
    crypto.open('review_service',envelope,ctx.metadata(app,version))取得已验证
    原文再调用 check_document_binding；版本不一致应先抛 VERSION_MISMATCH。
    生成'APR-'+uuid4().hex作为approval_id，用store.add_approval保存。
    返回approval_id/application_id/doc_version/status/replayed字段；
    approve映射APPROVED，reject映射REJECTED。
    同一事务写审批、processed_requests(action='approve')与SUCCESS审计。
    不用签名值作为去重依据，不因已批准状态阻止同一请求的合法重试。
    LabError须在事务外record_failure并重抛；不得继续归档。
    """
    stage = "input"
    application_id = "UNKNOWN"
    request_id = "UNKNOWN"
    try:
        canonical = canonicalize_manifest(manifest)
        application_id = manifest["application_id"]
        request_id = manifest["request_id"]
        fingerprint = sm3_hex(canonical)

        with ctx.store.transaction() as conn:
            stage = "authorization"
            ctx.require_principal(principal, conn)

            # 验签必须先于去重：账号或密钥被吊销时，重试也不能返回旧结果。
            stage = "signature"
            registry = ctx.store.registry(conn)
            verify_approval_signature(manifest, signature, principal,
                                      registry, ctx.crypto)

            stage = "idempotency"
            prior = ctx.store.request(conn, principal.actor_id, request_id)
            if prior is not None:
                if prior["action"] != "approve" or prior["fingerprint"] != fingerprint:
                    fail("REQUEST_CONFLICT")
                ctx.audit(conn, principal.actor_id, application_id, request_id,
                          "approve", "idempotency", "REPLAY")
                return dict(prior["result"], replayed=True)

            stage = "authorization"
            application = ctx.store.app(conn, application_id)
            authorize_action(principal, application, "approve")

            stage = "binding"
            if manifest["doc_version"] != application["doc_version"]:
                fail("VERSION_MISMATCH")

            stage = "freshness"
            validate_request_freshness(manifest, ctx.now())

            stage = "decrypt"
            document = ctx.store.document(conn, application_id,
                                          manifest["doc_version"])
            plaintext = ctx.crypto.open(
                "review_service", document["envelope"],
                ctx.metadata(application, manifest["doc_version"]))

            stage = "binding"
            check_document_binding(manifest, application, document, plaintext)

            stage = "commit"
            approval_id = "APR-" + uuid.uuid4().hex
            ctx.store.add_approval(conn, manifest, signature, approval_id)
            status = "APPROVED" if manifest["decision"] == "approve" else "REJECTED"
            result = {
                "approval_id": approval_id,
                "application_id": application_id,
                "doc_version": manifest["doc_version"],
                "status": status,
                "replayed": False,
            }
            ctx.store.save_request(conn, principal.actor_id, request_id,
                                   "approve", fingerprint, result)
            ctx.audit(conn, principal.actor_id, application_id, request_id,
                      "approve", "commit", "SUCCESS")
            return result
    except LabError as error:
        ctx.record_failure(principal, application_id, request_id,
                           "approve", stage, error)
        raise


def read_material(ctx, principal, application_id, request_id):
    """授权后读取并验证当前附件，成功返回原始 bytes。

    校验 ID；在事务内复核登录主体并获取 application。
    先调用 authorize_action 做 read 授权，
    再取得当前document并调用crypto.open('query_service',envelope,
    ctx.metadata(application,document['version']))。对解密结果重新计算SM3，
    与document.file_sm3不一致抛DOCUMENT_MISMATCH。
    成功在同一事务写operation='read'、stage='decrypt'的SUCCESS事件。
    未授权时crypto.open调用次数必须为0；失败不返回部分原文或空字节伪成功。
    LabError在事务外写record_failure，随后重抛。不要持久化解密结果。
    """
    stage = "input"
    try:
        if not valid_id(application_id) or not valid_id(request_id):
            fail("INVALID_INPUT")

        with ctx.store.transaction() as conn:
            stage = "authorization"
            ctx.require_principal(principal, conn)
            application = ctx.store.app(conn, application_id)
            authorize_action(principal, application, "read")

            stage = "decrypt"
            version = application["doc_version"]
            document = ctx.store.document(conn, application_id, version)
            plaintext = ctx.crypto.open(
                "query_service", document["envelope"],
                ctx.metadata(application, version))

            if calculate_file_sm3(plaintext) != document["file_sm3"]:
                fail("DOCUMENT_MISMATCH")

            ctx.audit(conn, principal.actor_id, application_id, request_id,
                      "read", "decrypt", "SUCCESS")
            return plaintext
    except LabError as error:
        ctx.record_failure(principal, application_id, request_id,
                           "read", stage, error)
        raise
