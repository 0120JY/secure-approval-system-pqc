"""公钥与签名的 Base64 / Hex 编解码工具。

对外统一采用 RFC 4648 标准字母表 + padding；解码要求严格且规范（canonical），
避免同一字节序列出现多种字符串表示。Hex 仅作为历史数据的只读兼容。
"""
import base64
import re

HEX128 = re.compile(r"[0-9a-fA-F]{128}\Z")


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def b64_to_bytes_strict(value, byte_len):
    """将 canonical Base64 严格解码为指定字节长度；失败返回 None。"""
    if not isinstance(value, str):
        return None
    try:
        raw = b64d(value)
    except (ValueError, TypeError, UnicodeError):
        return None
    if len(raw) != byte_len or b64e(raw) != value:
        return None
    return raw


def hex_to_bytes(value, byte_len):
    """将恰好 2*byte_len 个 hex 字符解码为字节；失败返回 None。"""
    if not isinstance(value, str) or len(value) != 2 * byte_len:
        return None
    try:
        return bytes.fromhex(value)
    except ValueError:
        return None


def coerce_to_b64(value, byte_len):
    """将 canonical Base64 或 hex 表示统一为 Base64；失败返回 None。

    优先识别 Base64（长度匹配且可规范往返），否则尝试 hex，用于兼容
    历史 Hex 数据与无 encoding 提示的旧调用。
    """
    if b64_to_bytes_strict(value, byte_len) is not None:
        return value
    raw = hex_to_bytes(value, byte_len)
    return b64e(raw) if raw is not None else None


def detect_encoding(value, byte_len):
    """识别字符串是 canonical Base64 还是 hex；两者皆非返回 None。"""
    if b64_to_bytes_strict(value, byte_len) is not None:
        return "base64"
    if hex_to_bytes(value, byte_len) is not None:
        return "hex"
    return None
