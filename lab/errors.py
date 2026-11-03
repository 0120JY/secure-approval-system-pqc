class LabError(Exception):
    """可呈现的业务错误；只记录code，不把异常原文写入审计。"""

    def __init__(self, code: str, message: str = ""):
        self.code = code
        self.message = message or code
        super().__init__(f"{code}: {self.message}")


MESSAGES = {
    "AUTH_FAILED": "账号或密码不正确，或账号已停用",
    "FORBIDDEN": "当前账号没有这项业务权限",
    "INVALID_INPUT": "输入字段或类型不符合约定",
    "NOT_FOUND": "业务对象不存在",
    "NO_DOCUMENT": "请先提交申请材料",
    "INVALID_STATE": "当前业务状态不允许这项操作",
    "SIGNATURE_INVALID": "审批记录签名验证失败",
    "IDENTITY_MISMATCH": "签名密钥、审批人和登录主体不匹配",
    "UNTRUSTED_KEY": "签名密钥不在有效的可信登记表中",
    "VERSION_MISMATCH": "审批记录与当前材料版本不一致",
    "DOCUMENT_MISMATCH": "审批记录与实际材料内容不一致",
    "REQUEST_EXPIRED": "请求超过有效时间范围",
    "REQUEST_CONFLICT": "同一请求标识对应了不同的业务内容",
    "CRYPTO_UNAVAILABLE": "密码服务暂不可用，本次操作没有完成",
    "INTEGRITY_ERROR": "密文、标签或关联元数据校验失败",
    "KEY_NOT_FOUND": "材料密钥不可用",
    "SERVICE_FORBIDDEN": "服务身份没有所请求的密码操作权限",
    "UNSUPPORTED_ALGORITHM": "当前签名算法不受支持",
}


def fail(code: str):
    raise LabError(code, MESSAGES.get(code, code))
