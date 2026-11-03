"""密码敏捷性配置：签名算法与密钥标识模板，支持环境变量与 JSON 覆盖。

系统默认签名算法已切换为 ML-DSA-65（后量子签名，直接替换 SM2）。
历史 SM2 密钥与 Hex 签名只读兼容：无算法提示的验签默认走 SM2
（``LEGACY_VERIFY_ALGORITHM``），与“新数据用 ML-DSA”互不影响。
"""
import json
import os

DEFAULT_SIGNING_ALGORITHM = "ML-DSA-65"
DEFAULT_LEGACY_VERIFY_ALGORITHM = "SM2"
DEFAULT_KEY_ID_TEMPLATE = "{actor_id}-{algorithm}-01"
DEFAULT_ALLOWED_ALGORITHMS = ("SM2", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87")


def _env(name, default):
    value = os.environ.get(name)
    return value.strip() if value else default


def _load_json_overrides():
    path = os.environ.get("AID_CRYPTO_CONFIG")
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


_OVERRIDES = _load_json_overrides()

SIGNING_ALGORITHM = _OVERRIDES.get(
    "signing_algorithm", _env("AID_SIGNING_ALGORITHM", DEFAULT_SIGNING_ALGORITHM))
# 无算法提示的验签默认算法：历史数据只读兼容，固定指向 SM2。
LEGACY_VERIFY_ALGORITHM = _OVERRIDES.get(
    "legacy_verify_algorithm",
    _env("AID_LEGACY_VERIFY_ALGORITHM", DEFAULT_LEGACY_VERIFY_ALGORITHM))
KEY_ID_TEMPLATE = _OVERRIDES.get(
    "key_id_template", _env("AID_SIGNING_KEY_ID_TEMPLATE", DEFAULT_KEY_ID_TEMPLATE))
# 新写入固定使用 Base64（兼容 PQC 变长公钥/签名）；Hex 仅用于历史数据只读。
WRITE_ENCODING = "base64"
ALLOWED_SIGNING_ALGORITHMS = tuple(_OVERRIDES.get(
    "allowed_signing_algorithms",
    _env("AID_ALLOWED_SIGNING_ALGORITHMS", ",".join(DEFAULT_ALLOWED_ALGORITHMS))
).split(","))


def key_id_for(actor_id, algorithm=None):
    """按配置模板生成签名密钥标识，默认仍产出 ``{actor_id}-{algorithm}-01``。"""
    return KEY_ID_TEMPLATE.format(actor_id=actor_id,
                                  algorithm=algorithm or SIGNING_ALGORITHM)
