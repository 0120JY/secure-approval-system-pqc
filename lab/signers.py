"""签名算法抽象层：Signer 接口、SM2 与 ML-DSA 实现、算法注册表。

业务层只依赖 Signer 契约；算法相关约束（字节长度、编码、r||s 结构、
曲线校验、FIPS 204 context）全部内聚在具体实现中。公钥与签名对外统一为
Base64，历史 Hex 仅作为 SM2 旧数据的只读兼容。

为兼容 SM2（64 字节）与 ML-DSA（3 KB+）的尺寸差异，接口做了五处微调：
1. 每个算法声明自己的尺寸与能力元数据（public_key_bytes / private_key_bytes /
   signature_bytes / signature_max_bytes / quantum_resistant / 编码约定）；
2. generate_keypair 仍返回 (private_key, public_key) 二元组，但私钥编码由
   private_key_encoding 声明（SM2 为 hex，ML-DSA 为 base64），对上层不透明；
3. sign / verify 增加可选 context 参数（FIPS 204 域分离，SM2 忽略）；
4. 编码/长度校验下放到 normalize_public_key / normalize_signature /
   detect_public_key_encoding，Crypto 不再知道具体字节长度；
5. 注册表改为“算法标识 → 零参工厂”，支持带参数集的 MLDSASigner。
"""
from abc import ABC, abstractmethod
import importlib
import secrets

from gmssl import sm2

from .crypto_encoding import (b64e, b64_to_bytes_strict, hex_to_bytes,
                              coerce_to_b64, detect_encoding, HEX128)
from .errors import fail

SM2_N = int(sm2.default_ecc_table["n"], 16)


def sm2_engine(private_key="", public_key=""):
    engine = sm2.CryptSM2(private_key=private_key, public_key=public_key)
    # 3.2.2构造器lstrip('04')会误删某些以04开头的坐标。
    # 本项目内部统一使用恰好128个hex字符的无前缀x||y，并恢复原值。
    engine.public_key = public_key.lower()
    return engine


def derive_public_key(private_key):
    """由 SM2 私钥推导公钥（x||y，128 hex），用于签名时的 ZA 计算。"""
    engine = sm2_engine(private_key=private_key)
    return engine._kg(int(private_key, 16), sm2.default_ecc_table["g"])


def new_sm2_keypair():
    # SM2签名私钥范围1..n-2，避开d=n-1时不存在的(1+d)逆元。
    private_key = f"{secrets.randbelow(SM2_N - 2) + 1:064x}"
    return private_key, derive_public_key(private_key)


def valid_public_key(public_key):
    """public_key 为 128 位 hex 时校验是否为 SM2 曲线上的合法点。"""
    if not isinstance(public_key, str) or not HEX128.fullmatch(public_key):
        return False
    x, y = int(public_key[:64], 16), int(public_key[64:], 16)
    p = int(sm2.default_ecc_table["p"], 16)
    a = int(sm2.default_ecc_table["a"], 16)
    b = int(sm2.default_ecc_table["b"], 16)
    return 0 <= x < p and 0 <= y < p and (y*y - x*x*x - a*x - b) % p == 0


class Signer(ABC):
    """签名算法插件契约。

    公钥与签名对外统一为 Base64；私钥入参暂为字符串材料（不引入
    HSM/KeyProvider，避免过度设计）。每个子类声明自己的尺寸与能力。
    """
    alg_id = ""
    public_key_bytes = 0
    signature_bytes = 0
    private_key_bytes = 0
    signature_max_bytes = None
    quantum_resistant = False
    public_key_encoding = "base64"
    private_key_encoding = "hex"  # SM2 历史私钥为 hex；ML-DSA 覆盖为 base64
    component_algs = ()

    @abstractmethod
    def generate_keypair(self):
        """返回 (private_key, public_key) 字符串二元组。"""

    @abstractmethod
    def sign(self, private_key, data, context=None):
        """使用私钥对 data 签名，返回 base64 签名。"""

    @abstractmethod
    def verify(self, public_key, data, signature, context=None):
        """public_key 与 signature 均为 base64；返回 bool。"""

    @abstractmethod
    def validate_public_key(self, public_key):
        """public_key 为 base64；返回 bool。"""

    def normalize_public_key(self, value, encoding=None):
        """把公钥字符串规范化为 Base64；失败返回 None。"""
        raise NotImplementedError

    def normalize_signature(self, value, encoding=None):
        """把签名字符串规范化为 Base64；失败返回 None。"""
        raise NotImplementedError

    def detect_public_key_encoding(self, value):
        """识别公钥字符串的编码，返回 'base64' / 'hex' / None。"""
        raise NotImplementedError


class SM2Signer(Signer):
    alg_id = "SM2"
    public_key_bytes = 64
    signature_bytes = 64
    private_key_bytes = 32
    signature_max_bytes = 64
    quantum_resistant = False
    public_key_encoding = "base64"
    private_key_encoding = "hex"

    def generate_keypair(self):
        private_key, public_key = new_sm2_keypair()
        return private_key, b64e(bytes.fromhex(public_key))

    def sign(self, private_key, data, context=None):
        # SM2-with-SM3 的 ZA 依赖公钥，须由私钥推导后传入引擎。
        # context 忽略：SM2 无原生 context，域分离由清单 schema 字段承担。
        public_key = derive_public_key(private_key)
        engine = sm2_engine(private_key=private_key, public_key=public_key)
        for _ in range(8):
            nonce = f"{secrets.randbelow(SM2_N - 1) + 1:064x}"
            signature = engine.sign_with_sm3(data, random_hex_str=nonce)
            if signature:
                return b64e(bytes.fromhex(signature))
        fail("CRYPTO_UNAVAILABLE")

    def verify(self, public_key, data, signature, context=None):
        public_hex = self._decode(public_key, self.public_key_bytes)
        if public_hex is None or not valid_public_key(public_hex):
            return False
        signature_hex = self._decode(signature, self.signature_bytes)
        if signature_hex is None:
            return False
        r, s = int(signature_hex[:64], 16), int(signature_hex[64:], 16)
        if not (1 <= r < SM2_N and 1 <= s < SM2_N):
            return False
        try:
            return bool(sm2_engine(public_key=public_hex).verify_with_sm3(signature_hex, data))
        except (ValueError, TypeError, ZeroDivisionError):
            return False

    def validate_public_key(self, public_key):
        public_hex = self._decode(public_key, self.public_key_bytes)
        return public_hex is not None and valid_public_key(public_hex)

    def normalize_public_key(self, value, encoding=None):
        if encoding == "hex":
            raw = hex_to_bytes(value, self.public_key_bytes)
            return b64e(raw) if raw is not None else None
        if encoding == "base64":
            return value if b64_to_bytes_strict(value, self.public_key_bytes) is not None else None
        return coerce_to_b64(value, self.public_key_bytes)

    def normalize_signature(self, value, encoding=None):
        if encoding == "hex":
            raw = hex_to_bytes(value, self.signature_bytes)
            return b64e(raw) if raw is not None else None
        if encoding == "base64":
            return value if b64_to_bytes_strict(value, self.signature_bytes) is not None else None
        return coerce_to_b64(value, self.signature_bytes)

    def detect_public_key_encoding(self, value):
        return detect_encoding(value, self.public_key_bytes)

    @staticmethod
    def _decode(value, byte_len):
        raw = b64_to_bytes_strict(value, byte_len)
        return raw.hex() if raw is not None else None


class MLDSASigner(Signer):
    """FIPS 204 ML-DSA（Dilithium）后量子签名，依赖 pqcrypto 提供原生实现。

    参数集编码进 alg_id（ML-DSA-44 / 65 / 87），尺寸与安全级别由此唯一确定；
    对外公钥与签名均为标准 Base64，私钥亦为 Base64（不再使用 hex）。
    """
    _PARAMS = {
        # 参数集: (模块名, 公钥字节, 私钥字节, 签名字节)
        "ML-DSA-44": ("ml_dsa_44", 1312, 2560, 2420),
        "ML-DSA-65": ("ml_dsa_65", 1952, 4032, 3309),
        "ML-DSA-87": ("ml_dsa_87", 2592, 4896, 4627),
    }
    quantum_resistant = True
    public_key_encoding = "base64"
    private_key_encoding = "base64"

    def __init__(self, parameter_set="ML-DSA-65"):
        if parameter_set not in self._PARAMS:
            fail("UNSUPPORTED_ALGORITHM")
        self.alg_id = parameter_set
        module_name, pk, sk, sig = self._PARAMS[parameter_set]
        self._module_name = module_name
        self.public_key_bytes = pk
        self.private_key_bytes = sk
        self.signature_bytes = sig
        self.signature_max_bytes = sig

    def _module(self):
        # 延迟导入：未安装 pqcrypto 的 SM2 环境仍可启动，仅 ML-DSA 操作失败。
        try:
            return importlib.import_module(f"pqcrypto.sign.{self._module_name}")
        except ImportError:
            fail("CRYPTO_UNAVAILABLE")

    def generate_keypair(self):
        module = self._module()
        # pqcrypto 的 keygen 返回 (public_key, secret_key)，这里按契约翻转为
        # (private_key, public_key)，两者均为 bytes，统一编码为 Base64。
        public_key, private_key = module.keygen()
        return b64e(private_key), b64e(public_key)

    def sign(self, private_key, data, context=None):
        module = self._module()
        raw_sk = b64_to_bytes_strict(private_key, self.private_key_bytes)
        if raw_sk is None:
            fail("CRYPTO_UNAVAILABLE")
        signature = module.sign(raw_sk, data, context=context)
        return b64e(bytes(signature))

    def verify(self, public_key, data, signature, context=None):
        raw_pk = b64_to_bytes_strict(public_key, self.public_key_bytes)
        raw_sig = b64_to_bytes_strict(signature, self.signature_bytes)
        if raw_pk is None or raw_sig is None:
            return False
        try:
            # pqcrypto 成功返回 None，失败抛 InvalidSignatureError(ValueError)。
            self._module().verify(raw_pk, data, raw_sig, context=context)
            return True
        except (ValueError, TypeError):
            return False

    def validate_public_key(self, public_key):
        return b64_to_bytes_strict(public_key, self.public_key_bytes) is not None

    def normalize_public_key(self, value, encoding=None):
        # ML-DSA 无历史 Hex 形态，只接受严格 Base64。
        if encoding not in (None, "base64"):
            return None
        return value if b64_to_bytes_strict(value, self.public_key_bytes) is not None else None

    def normalize_signature(self, value, encoding=None):
        if encoding not in (None, "base64"):
            return None
        return value if b64_to_bytes_strict(value, self.signature_bytes) is not None else None

    def detect_public_key_encoding(self, value):
        return "base64" if b64_to_bytes_strict(value, self.public_key_bytes) is not None else None


def _ml_dsa_factory(parameter_set):
    def factory():
        return MLDSASigner(parameter_set)
    return factory


SIGNERS = {
    "SM2": SM2Signer,
    "ML-DSA-44": _ml_dsa_factory("ML-DSA-44"),
    "ML-DSA-65": _ml_dsa_factory("ML-DSA-65"),
    "ML-DSA-87": _ml_dsa_factory("ML-DSA-87"),
}


def get_signer(alg):
    try:
        factory = SIGNERS[alg]
    except (KeyError, TypeError):
        fail("UNSUPPORTED_ALGORITHM")
    return factory()
